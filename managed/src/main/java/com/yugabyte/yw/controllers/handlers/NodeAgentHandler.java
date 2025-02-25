// Copyright (c) Yugabyte, Inc.

package com.yugabyte.yw.controllers.handlers;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.typesafe.config.Config;
import com.yugabyte.yw.common.ConfigHelper;
import com.yugabyte.yw.common.ConfigHelper.ConfigType;
import com.yugabyte.yw.common.PlatformScheduler;
import com.yugabyte.yw.common.PlatformServiceException;
import com.yugabyte.yw.common.Util;
import com.yugabyte.yw.common.certmgmt.CertificateHelper;
import com.yugabyte.yw.controllers.JWTVerifier;
import com.yugabyte.yw.controllers.JWTVerifier.ClientType;
import com.yugabyte.yw.forms.NodeAgentForm;
import com.yugabyte.yw.models.Customer;
import com.yugabyte.yw.models.NodeAgent;
import com.yugabyte.yw.models.NodeAgent.State;
import io.ebean.annotation.Transactional;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.inject.Inject;
import javax.inject.Singleton;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import play.mvc.Http.Status;

@Slf4j
@Singleton
public class NodeAgentHandler {
  public static final String NODE_AGENT_ID_CLAIM = "nodeAgentId";
  public static final String NODE_AGENT_USER_ID_CLAIM = "userId";
  public static final String NODE_AGENT_CUSTOMER_ID_CLAIM = "customerId";
  public static final String CLAIM_SESSION_PROPERTY = "jwt-claims";

  public static final int CERT_EXPIRY_YEARS = 5;

  public static final Duration UPDATER_SERVICE_INITIAL_DELAY = Duration.ofMinutes(1);
  public static final Duration UPDATER_SERVICE_INTERVAL = Duration.ofMinutes(10);

  public static final Set<State> UPDATABLE_STATES_BY_NODE_AGENT =
      ImmutableSet.<State>builder().add(State.UPGRADING, State.LIVE).build();

  private final Config appConfig;
  private final PlatformScheduler platformScheduler;
  private final ConfigHelper configHelper;

  @Inject
  public NodeAgentHandler(
      Config appConfig, ConfigHelper configHelper, PlatformScheduler platformScheduler) {
    this.appConfig = appConfig;
    this.configHelper = configHelper;
    this.platformScheduler = platformScheduler;
    this.platformScheduler.schedule(
        NodeAgentHandler.class.getSimpleName(),
        UPDATER_SERVICE_INITIAL_DELAY,
        UPDATER_SERVICE_INTERVAL,
        this::updaterService);
  }

  /**
   * This method is run in interval. Some node agents may not be responding at the moment. Once they
   * come up, they may recover from their states and change to LIVE. Then, they are notified to
   * upgrade. After that, this method becomes idle. It can be improved to do in batches.
   */
  @VisibleForTesting
  void updaterService() {
    try {
      String softwareVersion =
          Objects.requireNonNull(
              (String) configHelper.getConfig(ConfigType.SoftwareVersion).get("version"));
      Customer.getAll()
          .stream()
          .map(c -> c.uuid)
          .flatMap(
              cUuid -> {
                log.info("Fetching updatable node agents for customer {}", cUuid);
                return NodeAgent.getUpdatableNodeAgents(cUuid, softwareVersion).stream();
              })
          .forEach(
              n -> {
                log.info("Initiating upgrade for node agent {}", n.uuid);
                n.state = State.UPGRADE;
                n.save();
              });
    } catch (Exception e) {
      log.error("Error occurred in updater service", e);
    }
  }

  private Path getNodeAgentBaseCertDirectory(NodeAgent nodeAgent) {
    return Paths.get(
        appConfig.getString("yb.storage.path"),
        "node-agents",
        "certs",
        nodeAgent.customerUuid.toString(),
        nodeAgent.uuid.toString());
  }

  private Path getOrCreateCertDirectory(NodeAgent nodeAgent, String certDir) {
    Path certDirPath = getNodeAgentBaseCertDirectory(nodeAgent).resolve(certDir);
    log.info("Creating node agent cert directory {}", certDirPath);
    return Util.getOrCreateDir(certDirPath);
  }

  // Certs are created in each directory <base-cert-dir>/<index>/.
  // The index keeps increasing.
  private Path getOrCreateNextCertDirectory(NodeAgent nodeAgent) {
    String certDirPath = nodeAgent.config.get(NodeAgent.CERT_DIR_PATH_PROPERTY);
    if (StringUtils.isBlank(certDirPath)) {
      return getOrCreateCertDirectory(nodeAgent, "0");
    }
    String certDir = Paths.get(certDirPath).getFileName().toString();
    return getOrCreateCertDirectory(nodeAgent, String.valueOf(Integer.parseInt(certDir) + 1));
  }

  private Pair<X509Certificate, KeyPair> createRootCert(
      NodeAgent nodeAgent, String certPath, String keyPath) {
    try {
      String certLabel = nodeAgent.uuid.toString();
      KeyPair keyPair = CertificateHelper.getKeyPairObject();
      X509Certificate x509 =
          CertificateHelper.generateCACertificate(certLabel, keyPair, CERT_EXPIRY_YEARS);
      CertificateHelper.writeCertFileContentToCertPath(x509, certPath);
      CertificateHelper.writeKeyFileContentToKeyPath(keyPair.getPrivate(), keyPath);
      return new ImmutablePair<>(x509, keyPair);
    } catch (RuntimeException e) {
      log.error("Failed to create root cert for node agent {}", nodeAgent.uuid, e);
      throw e;
    } catch (Exception e) {
      log.error("Failed to create root cert for node agent {}", nodeAgent.uuid, e);
      throw new RuntimeException(e.getMessage(), e);
    }
  }

  private Pair<X509Certificate, KeyPair> createServerCert(
      NodeAgent nodeAgent,
      X509Certificate caCert,
      PrivateKey caPrivateKey,
      String serverCertPath,
      String serverKeyPath) {
    try {
      Map<String, Integer> sans =
          ImmutableMap.<String, Integer>builder().put(nodeAgent.ip, GeneralName.iPAddress).build();

      // Add the security provider in case createSignedCertificate was never called.
      KeyPair keyPair = CertificateHelper.getKeyPairObject();
      // The first entry will be the certificate that needs to sign the necessary certificate.
      X500Name subject = new JcaX509CertificateHolder(caCert).getSubject();
      X509Certificate x509 =
          CertificateHelper.createAndSignCertificate(
              nodeAgent.ip,
              subject,
              keyPair,
              caCert,
              caPrivateKey,
              sans,
              appConfig.getInt("yb.tlsCertificate.server.maxLifetimeInYears"));
      CertificateHelper.writeCertFileContentToCertPath(x509, serverCertPath);
      CertificateHelper.writeKeyFileContentToKeyPath(keyPair.getPrivate(), serverKeyPath);
      return new ImmutablePair<>(x509, keyPair);
    } catch (RuntimeException e) {
      log.error("Failed to create server cert for node agent {}", nodeAgent.uuid, e);
      throw e;
    } catch (Exception e) {
      log.error("Failed to create server cert for node agent {}", nodeAgent.uuid, e);
      throw new RuntimeException(e.getMessage(), e);
    }
  }

  private void updateNodeAgentCerts(NodeAgent nodeAgent) {
    Path currentCertDirPath = Paths.get(nodeAgent.config.get(NodeAgent.CERT_DIR_PATH_PROPERTY));
    Path newCertDirPath = getOrCreateNextCertDirectory(nodeAgent);
    if (!Files.exists(newCertDirPath)) {
      throw new IllegalStateException(
          String.format("New cert directory %s does not exist", newCertDirPath));
    }
    // Point to the new directory and persist in the DB before deleting.
    nodeAgent.config.put(NodeAgent.CERT_DIR_PATH_PROPERTY, newCertDirPath.toString());
    nodeAgent.save();
    try {
      // Delete the old cert directory.
      FileUtils.deleteDirectory(currentCertDirPath.toFile());
    } catch (IOException e) {
      // Ignore error.
      log.warn("Error deleting old cert directory {}", currentCertDirPath, e);
    }
  }

  private Pair<X509Certificate, KeyPair> generateNodeAgentCerts(NodeAgent nodeAgent, Path dirPath) {
    try {
      String caCertPath = dirPath.resolve(NodeAgent.ROOT_CA_CERT_NAME).toString();
      String caKeyPath = dirPath.resolve(NodeAgent.ROOT_CA_KEY_NAME).toString();
      String serverCertPath = dirPath.resolve(NodeAgent.SERVER_CERT_NAME).toString();
      String serverKeyPath = dirPath.resolve(NodeAgent.SERVER_KEY_NAME).toString();

      Pair<X509Certificate, KeyPair> pair = createRootCert(nodeAgent, caCertPath, caKeyPath);
      log.info(
          "Generated root cert for node agent: {} at key path: {} and cert path: {}",
          nodeAgent.uuid,
          caKeyPath,
          caCertPath);

      Pair<X509Certificate, KeyPair> serverPair =
          createServerCert(
              nodeAgent,
              pair.getLeft(),
              pair.getRight().getPrivate(),
              serverCertPath,
              serverKeyPath);

      log.info(
          "Generated self-signed server cert for node agent: {} at key path: {} and cert path: {}",
          nodeAgent.uuid,
          serverKeyPath,
          serverKeyPath);
      return serverPair;
    } catch (RuntimeException e) {
      log.error("Failed to generate certs for node agent {}", nodeAgent.uuid, e);
      throw e;
    } catch (Exception e) {
      log.error("Failed to generate certs for node agent {}", nodeAgent.uuid, e);
      throw new RuntimeException(e.getMessage(), e);
    }
  }

  private PublicKey getPublicKeyFromCert(byte[] content) {
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      X509Certificate cert =
          (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(content));
      return cert.getPublicKey();
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException(e.getMessage(), e);
    }
  }

  private PrivateKey getPrivateKey(byte[] content) {
    return CertificateHelper.getPrivateKey(new String(content));
  }

  /**
   * Returns the public key of the given node agent.
   *
   * @param nodeAgentUuid node agent UUID.
   * @return the public key.
   */
  public PublicKey getNodeAgentPublicKey(UUID nodeAgentUuid) {
    Optional<NodeAgent> nodeAgentOp = NodeAgent.maybeGet(nodeAgentUuid);
    if (!nodeAgentOp.isPresent()) {
      throw new RuntimeException(String.format("Node agent %s does not exist", nodeAgentUuid));
    }
    return getPublicKeyFromCert(nodeAgentOp.get().getServerCert());
  }

  public PrivateKey getNodeAgentPrivateKey(UUID nodeAgentUuid) {
    Optional<NodeAgent> nodeAgentOp = NodeAgent.maybeGet(nodeAgentUuid);
    if (!nodeAgentOp.isPresent()) {
      throw new RuntimeException(String.format("Node agent %s does not exist", nodeAgentUuid));
    }
    return getPrivateKey(nodeAgentOp.get().getServerKey());
  }

  /**
   * Returns the JWT to authenticate a client request to the given node agent.
   *
   * @param nodeAgentUuid node agent UUID.
   * @return the JWT for sending request to the node agent.
   */
  public String getClientToken(UUID nodeAgentUuid, UUID userUuid) {
    PrivateKey privateKey = getNodeAgentPrivateKey(nodeAgentUuid);
    return Jwts.builder()
        .setIssuer("https://www.yugabyte.com")
        .setSubject(ClientType.NODE_AGENT.name())
        .setIssuedAt(Date.from(Instant.now()))
        .setExpiration(Date.from(Instant.now().plusSeconds(600)))
        .claim(JWTVerifier.CLIENT_ID_CLAIM, nodeAgentUuid.toString())
        .claim(JWTVerifier.USER_ID_CLAIM, userUuid.toString())
        .signWith(SignatureAlgorithm.RS256, privateKey)
        .compact();
  }

  /**
   * Registers the node agent to platform to set up the authentication keys.
   *
   * @param nodeAgent Partially populated node agent.
   * @return the fully populated node agent.
   */
  @Transactional
  public NodeAgent register(UUID customerUuid, NodeAgentForm payload) {
    Optional<NodeAgent> nodeAgentOp = NodeAgent.maybeGetByIp(payload.ip);
    if (nodeAgentOp.isPresent()) {
      throw new PlatformServiceException(Status.BAD_REQUEST, "Node agent is already registered");
    }
    NodeAgent nodeAgent = payload.toNodeAgent(customerUuid);
    // Save within the transaction to get DB generated column values.
    nodeAgent.saveState(State.REGISTERING);
    Path certDirPath = getOrCreateNextCertDirectory(nodeAgent);
    Pair<X509Certificate, KeyPair> serverPair = generateNodeAgentCerts(nodeAgent, certDirPath);
    nodeAgent.config.put(NodeAgent.CERT_DIR_PATH_PROPERTY, certDirPath.toString());
    nodeAgent.save();

    X509Certificate serverCert = serverPair.getLeft();
    KeyPair serverKeyPair = serverPair.getRight();
    // Add the contents to the response.
    nodeAgent.config =
        ImmutableMap.<String, String>builder()
            .putAll(nodeAgent.config)
            .put(NodeAgent.SERVER_CERT_PROPERTY, CertificateHelper.getAsPemString(serverCert))
            .put(
                NodeAgent.SERVER_KEY_PROPERTY,
                CertificateHelper.getAsPemString(serverKeyPair.getPrivate()))
            .build();
    return nodeAgent;
  }

  /**
   * Returns the node agent with the given IDs.
   *
   * @param customerUuid customer UUID.
   * @param nodeAgentUuid node agent UUID.
   * @return the node agent.
   */
  public NodeAgent get(UUID customerUuid, UUID nodeAgentUuid) {
    return NodeAgent.getOrBadRequest(customerUuid, nodeAgentUuid);
  }

  /**
   * Updates the current state of the node agent.
   *
   * @param customerUuid customer UUID.
   * @param nodeAgentUuid node agent UUID.
   * @param payload request payload.
   * @return the node agent.
   */
  public NodeAgent updateState(UUID customerUuid, UUID nodeAgentUuid, NodeAgentForm payload) {
    NodeAgent nodeAgent = NodeAgent.getOrBadRequest(customerUuid, nodeAgentUuid);
    nodeAgent.validateStateTransition(payload.state);
    if (!UPDATABLE_STATES_BY_NODE_AGENT.contains(payload.state)) {
      throw new PlatformServiceException(Status.BAD_REQUEST, "Invalid state " + payload.state);
    }
    State currentState = nodeAgent.state;
    nodeAgent.state = payload.state;
    if (currentState == State.UPGRADING && payload.state == State.LIVE) {
      // Node agent is ready after an upgrade.
      nodeAgent.version = payload.version;
      updateNodeAgentCerts(nodeAgent);
    } else {
      nodeAgent.save();
    }
    return nodeAgent;
  }

  /**
   * Updates the registration.
   *
   * @param customerUuid customer UUID.
   * @param nodeAgentUuid node agent UUID.
   * @return the node agent.
   */
  public NodeAgent updateRegistration(UUID customerUuid, UUID nodeAgentUuid) {
    NodeAgent nodeAgent = NodeAgent.getOrBadRequest(customerUuid, nodeAgentUuid);
    nodeAgent.ensureState(State.UPGRADING);
    Path certDirPath = getOrCreateNextCertDirectory(nodeAgent);
    Pair<X509Certificate, KeyPair> serverPair = generateNodeAgentCerts(nodeAgent, certDirPath);
    X509Certificate serverCert = serverPair.getLeft();
    KeyPair serverKeyPair = serverPair.getRight();
    // Add the contents to the response.
    nodeAgent.config =
        ImmutableMap.<String, String>builder()
            .putAll(nodeAgent.config)
            .put(NodeAgent.SERVER_CERT_PROPERTY, CertificateHelper.getAsPemString(serverCert))
            .put(
                NodeAgent.SERVER_KEY_PROPERTY,
                CertificateHelper.getAsPemString(serverKeyPair.getPrivate()))
            .build();
    return nodeAgent;
  }

  /**
   * Unregisters the node agent from platform.
   *
   * @param uuid the node UUID.
   */
  public void unregister(UUID uuid) {
    NodeAgent.maybeGet(uuid)
        .ifPresent(
            nodeAgent -> {
              Path basePath = getNodeAgentBaseCertDirectory(nodeAgent);
              nodeAgent.delete();
              try {
                FileUtils.deleteDirectory(basePath.toFile());
              } catch (IOException e) {
                log.error("Failed to clean up {}", basePath, e);
              }
            });
  }
}

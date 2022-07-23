package com.yugabyte.yw.controllers;

import com.google.common.net.HostAndPort;
import com.google.inject.Inject;
import com.yugabyte.yw.common.PlatformServiceException;
import com.yugabyte.yw.common.config.RuntimeConfigFactory;
import com.yugabyte.yw.common.services.YBClientService;
import com.yugabyte.yw.forms.PlatformResults;
import com.yugabyte.yw.models.Customer;
import com.yugabyte.yw.models.Universe;
import io.swagger.annotations.ApiOperation;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yb.client.CreateCDCStreamResponse;
import org.yb.client.ListCDCStreamsResponse;
import org.yb.client.YBClient;
import org.yb.master.MasterReplicationOuterClass.IdTypePB;
import org.yb.util.NetUtil;
import play.mvc.Result;

public class UniverseCdcStreamController extends AuthenticatedController {
  private static final Logger LOG = LoggerFactory.getLogger(UniverseCdcStreamController.class);

  @Inject private RuntimeConfigFactory runtimeConfigFactory;
  @Inject private YBClientService ybClientService;

  public void checkCloud() {
    if (!runtimeConfigFactory.globalRuntimeConf().getBoolean("yb.cloud.enabled")) {
      throw new PlatformServiceException(
        METHOD_NOT_ALLOWED, "CDC Stream management is not available.");
    }
  }

  @ApiOperation(
    value = "List CDC Streams for a cluster",
    notes = "List CDC Streams for a cluster"
  )
  public Result listCdcStreams(UUID customerUUID, UUID universeUUID) {
    checkCloud();

    Customer customer = Customer.getOrBadRequest(customerUUID);
    Universe universe = Universe.getValidUniverseOrBadRequest(universeUUID, customer);

    String masterAddresses = universe.getMasterAddresses();
    String certificate = universe.getCertificateNodetoNode();

    YBClient client = null;
    try {
      client = ybClientService.getClient(masterAddresses, certificate);
      LOG.error("Got client");

      ListCDCStreamsResponse response = client.listCDCStreams(null, null, IdTypePB.TABLE_ID);
      return PlatformResults.withData(response);
    } catch (Exception e) {
      LOG.error("Error while querying CDC streams: ", e);
      throw new RuntimeException(e);
    } finally {
      ybClientService.closeClient(client, masterAddresses);
    }
  }

  @ApiOperation(
    value = "Create CDC Stream for a cluster",
    notes = "Create CDC Stream for a cluster"
  )
  public Result createCdcStream(UUID customerUUID, UUID universeUUID) {
    checkCloud();

    Customer customer = Customer.getOrBadRequest(customerUUID);
    Universe universe = Universe.getValidUniverseOrBadRequest(universeUUID, customer);

    String masterAddresses = universe.getMasterAddresses();
    String certificate = universe.getCertificateNodetoNode();

    YBClient client = null;
    try {
      client = ybClientService.getClient(masterAddresses, certificate);

      List<HostAndPort> hps = NetUtil.parseStrings(masterAddresses, 7100);
      CreateCDCStreamResponse response = client.createCDCStream(hps.get(0), null, "yugabyte", "PROTO", "CHANGE");

      return PlatformResults.withData(response);
    } catch (Exception e) {
      LOG.error("Error while querying CDC streams: ", e);
      throw new RuntimeException(e);
    } finally {
      ybClientService.closeClient(client, masterAddresses);
    }
  }

}

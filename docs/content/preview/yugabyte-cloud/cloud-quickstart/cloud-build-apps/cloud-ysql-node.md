---
title: Build a Node.js application that uses YSQL
headerTitle: Build a Node.js application
description: Build a simple Node.js application using the driver and using the YSQL API to connect to and interact with a YugabyteDB Managed cluster.
headContent: "Client driver: node-postgres"
menu:
  preview_yugabyte-cloud:
    parent: cloud-build-apps
    name: Node.js
    identifier: cloud-node
    weight: 400
type: docs
---

The following tutorial shows a small [Node.js application](https://github.com/yugabyte/yugabyte-simple-node-app) that connects to a YugabyteDB cluster using the [node-postgres module](../../../../reference/drivers/ysql-client-drivers/#node-postgres) and performs basic SQL operations. Use the application as a template to get started with YugabyteDB Managed in Node.js.

## Prerequisites

In addition to the latest version of [Node.js](https://nodejs.org/en/download/), this tutorial requires the following.

### YugabyteDB Managed

- You have a cluster deployed in YugabyteDB Managed. To get started, use the [Quick start](../../).
- You downloaded the cluster CA certificate and added your computer to the cluster IP allow list. Refer to [Before you begin](../cloud-add-ip/).

## Clone the application from GitHub

Clone the sample application to your computer:

```sh
git clone https://github.com/YugabyteDB-Samples/yugabyte-simple-node-app.git && cd yugabyte-simple-node-app
```

## Provide connection parameters

The application needs to establish a connection to the YugabyteDB cluster. To do this:

1. Open the `sample-app.js` file.

2. Set the following configuration parameter constants:

    - **host** - the host name of your YugabyteDB cluster. To obtain a YugabyteDB Managed cluster host name, sign in to YugabyteDB Managed, select your cluster on the **Clusters** page, and click **Settings**. The host is displayed under **Connection Parameters**.
    - **port** - the port number that will be used by the driver (the default YugabyteDB YSQL port is 5433).
    - **database** - the name of the database you are connecting to (the default database is named `yugabyte`).
    - **user** and **password** - the username and password for the YugabyteDB database. If you are using the credentials you created when deploying a cluster in YugabyteDB Managed, these can be found in the credentials file you downloaded.
    - **ssl** - YugabyteDB Managed [requires SSL connections](../../../cloud-secure-clusters/cloud-authentication/#ssl-modes-in-ysql). To enable `verify-ca` SSL mode, the `rejectUnauthorized` property is set to `true` to require root certificate chain validation; replace `path_to_your_root_certificate` with the full path to the YugabyteDB Managed cluster CA certificate.

3. Save the file.

## Build and run the application

Install the node-postgres module.

```sh
npm install pg
```

Install the [async](https://github.com/caolan/async) utility:

```sh
npm install --save async
```

Start the application.

```sh
$ node sample-app.js
```

You should see output similar to the following:

```output
>>>> Successfully connected to YugabyteDB!
>>>> Successfully created table DemoAccount.
>>>> Selecting accounts:
name = Jessica, age = 28, country = USA, balance = 10000
name = John, age = 28, country = Canada, balance = 9000
>>>> Transferred 800 between accounts.
>>>> Selecting accounts:
name = Jessica, age = 28, country = USA, balance = 9200
name = John, age = 28, country = Canada, balance = 9800
```

You have successfully executed a basic Node.js application that works with YugabyteDB Managed.

## Explore the application logic

Open the `sample-app.js` file in the `yugabyte-simple-node-app` folder to review the methods.

### connect

The `connect` method establishes a connection with your cluster via the node-postgres driver.

```js
try {
    client = new pg.Client(config);

    await client.connect();

    console.log('>>>> Connected to YugabyteDB!');

    callbackHadler();
} catch (err) {
    callbackHadler(err);
}
```

### createDatabase

The `createDatabase` method uses PostgreSQL-compliant DDL commands to create a sample database.

```js
try {
    var stmt = 'DROP TABLE IF EXISTS DemoAccount';

    await client.query(stmt);

    stmt = `CREATE TABLE DemoAccount (
        id int PRIMARY KEY,
        name varchar,
        age int,
        country varchar,
        balance int)`;

    await client.query(stmt);

    stmt = `INSERT INTO DemoAccount VALUES
        (1, 'Jessica', 28, 'USA', 10000),
        (2, 'John', 28, 'Canada', 9000)`;

    await client.query(stmt);

    console.log('>>>> Successfully created table DemoAccount.');

    callbackHadler();
} catch (err) {
    callbackHadler(err);
}
```

### selectAccounts

The `selectAccounts` method queries your distributed data using the SQL `SELECT` statement.

```js
try {
    const res = await client.query('SELECT name, age, country, balance FROM DemoAccount');
    var row;

    for (i = 0; i < res.rows.length; i++) {
        row = res.rows[i];

        console.log('name = %s, age = %d, country = %s, balance = %d',
            row.name, row.age, row.country, row.balance);
    }

    callbackHadler();
} catch (err) {
    callbackHadler(err);
}
```

### transferMoneyBetweenAccounts

The `transferMoneyBetweenAccounts` method updates your data consistently with distributed transactions.

```js
try {
    await client.query('BEGIN TRANSACTION');

    await client.query('UPDATE DemoAccount SET balance = balance - ' + amount + ' WHERE name = \'Jessica\'');
    await client.query('UPDATE DemoAccount SET balance = balance + ' + amount + ' WHERE name = \'John\'');
    await client.query('COMMIT');

    console.log('>>>> Transferred %d between accounts.', amount);

    callbackHadler();
} catch (err) {
    callbackHadler(err);
}
```

## Learn more

[node-postgres module](../../../../reference/drivers/ysql-client-drivers/#node-postgres)

[Explore more applications](../../../cloud-examples/)

[Deploy clusters in YugabyteDB Managed](../../../cloud-basics)

[Connect to applications in YugabyteDB Managed](../../../cloud-connect/connect-applications/)

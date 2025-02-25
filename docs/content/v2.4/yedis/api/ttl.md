---
title: TTL
linkTitle: TTL
description: TTL
menu:
  v2.4:
    parent: api-yedis
    weight: 2470
type: docs
---

## Synopsis

<b>`TTL key`</b><br>
Returns the remaining time to live of a key that has a timeout, in seconds.

## Return value

Returns TTL in seconds, encoded as integer response.

## Examples

You can do this as shown below.

```sh
$ SET yugakey "Yugabyte"
```

```
"OK"
```

```sh
$ EXPIRE yugakey 10
```

```
(integer) 1
```

```sh
$ TTL yugakey
```

```
(integer) 10
```

## See also

[`set`](../set/), [`expire`](../expire/), [`expireat`](../expireat/), [`pttl`](../pttl/)

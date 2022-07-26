package com.yugabyte.yw.common.cdc;

import java.util.List;

final public class CdcStreamDeleteResponse {
  final private List<String> notFoundStreamIds;

  public CdcStreamDeleteResponse(List<String> notFoundStreamIds) {
    this.notFoundStreamIds = notFoundStreamIds;
  }

  public List<String> getNotFoundStreamIds() {
    return notFoundStreamIds;
  }

}

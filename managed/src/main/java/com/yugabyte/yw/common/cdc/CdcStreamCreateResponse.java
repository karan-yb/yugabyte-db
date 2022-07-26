package com.yugabyte.yw.common.cdc;

final public class CdcStreamCreateResponse {
  private final String streamId;

  public CdcStreamCreateResponse(String streamId) {
    this.streamId = streamId;
  }


  public String getStreamId() {
    return streamId;
  }

}

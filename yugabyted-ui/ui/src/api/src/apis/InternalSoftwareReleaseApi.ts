// tslint:disable
/**
 * Yugabyte Cloud
 * YugabyteDB as a Service
 *
 * The version of the OpenAPI document: v1
 * Contact: support@yugabyte.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { useQuery, useInfiniteQuery, useMutation, UseQueryOptions, UseInfiniteQueryOptions, UseMutationOptions } from 'react-query';
import Axios from '../runtime';
import type { AxiosInstance } from 'axios';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import type {
  ApiError,
  BatchAddAccountSoftwareTrackRequest,
  SoftwareReleaseListResponse,
  SoftwareReleaseResponse,
  SoftwareReleaseSpec,
  SoftwareReleaseTrackListPagedResponse,
  SoftwareReleaseTrackResponse,
  SoftwareReleaseTrackSpec,
} from '../models';

export interface BatchAddTracksForQuery {
  accountId: string;
  BatchAddAccountSoftwareTrackRequest?: BatchAddAccountSoftwareTrackRequest;
}
export interface CreateReleaseForQuery {
  trackId: string;
  SoftwareReleaseSpec?: SoftwareReleaseSpec;
}
export interface CreateTrackForQuery {
  SoftwareReleaseTrackSpec?: SoftwareReleaseTrackSpec;
}
export interface DeleteReleaseForQuery {
  trackId: string;
  releaseId: string;
}
export interface DeleteTrackForQuery {
  trackId: string;
}
export interface ListReleasesOnTrackForQuery {
  trackId: string;
  limit?: number;
  continuation_token?: string;
}
export interface ListTracksForQuery {
  limit?: number;
  continuation_token?: string;
}
export interface RemoveTrackForQuery {
  accountId: string;
  trackId: string;
}
export interface UpdateReleaseForQuery {
  trackId: string;
  releaseId: string;
  SoftwareReleaseSpec?: SoftwareReleaseSpec;
}

/**
 * Batch Add release tracks to account
 * Add release tracks to account
 */


export const batchAddTracksMutate = (
  body: BatchAddTracksForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  const url = '/private/accounts/{accountId}/software/tracks'.replace(`{${'accountId'}}`, encodeURIComponent(String(body.accountId)));
  // eslint-disable-next-line
  // @ts-ignore
  delete body.accountId;
  return Axios<unknown>(
    {
      url,
      method: 'POST',
      data: body.BatchAddAccountSoftwareTrackRequest
    },
    customAxiosInstance
  );
};

export const useBatchAddTracksMutation = <Error = ApiError>(
  options?: {
    mutation?:UseMutationOptions<unknown, Error>,
    customAxiosInstance?: AxiosInstance;
  }
) => {
  const {mutation: mutationOptions, customAxiosInstance} = options ?? {};
  // eslint-disable-next-line
  // @ts-ignore
  return useMutation<unknown, Error, BatchAddTracksForQuery, unknown>((props) => {
    return  batchAddTracksMutate(props, customAxiosInstance);
  }, mutationOptions);
};


/**
 * Create a software release
 * Create a software release
 */


export const createReleaseMutate = (
  body: CreateReleaseForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  const url = '/private/software/tracks/{trackId}/releases'.replace(`{${'trackId'}}`, encodeURIComponent(String(body.trackId)));
  // eslint-disable-next-line
  // @ts-ignore
  delete body.trackId;
  return Axios<SoftwareReleaseResponse>(
    {
      url,
      method: 'POST',
      data: body.SoftwareReleaseSpec
    },
    customAxiosInstance
  );
};

export const useCreateReleaseMutation = <Error = ApiError>(
  options?: {
    mutation?:UseMutationOptions<SoftwareReleaseResponse, Error>,
    customAxiosInstance?: AxiosInstance;
  }
) => {
  const {mutation: mutationOptions, customAxiosInstance} = options ?? {};
  // eslint-disable-next-line
  // @ts-ignore
  return useMutation<SoftwareReleaseResponse, Error, CreateReleaseForQuery, unknown>((props) => {
    return  createReleaseMutate(props, customAxiosInstance);
  }, mutationOptions);
};


/**
 * Create a DB software release track
 * Create a DB software release track
 */


export const createTrackMutate = (
  body: CreateTrackForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  const url = '/private/software/tracks';
  return Axios<SoftwareReleaseTrackResponse>(
    {
      url,
      method: 'POST',
      data: body.SoftwareReleaseTrackSpec
    },
    customAxiosInstance
  );
};

export const useCreateTrackMutation = <Error = ApiError>(
  options?: {
    mutation?:UseMutationOptions<SoftwareReleaseTrackResponse, Error>,
    customAxiosInstance?: AxiosInstance;
  }
) => {
  const {mutation: mutationOptions, customAxiosInstance} = options ?? {};
  // eslint-disable-next-line
  // @ts-ignore
  return useMutation<SoftwareReleaseTrackResponse, Error, CreateTrackForQuery, unknown>((props) => {
    return  createTrackMutate(props, customAxiosInstance);
  }, mutationOptions);
};


/**
 * Delete a software release
 * Delete a software release
 */


export const deleteReleaseMutate = (
  body: DeleteReleaseForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  const url = '/private/software/tracks/{trackId}/releases/{releaseId}'.replace(`{${'trackId'}}`, encodeURIComponent(String(body.trackId))).replace(`{${'releaseId'}}`, encodeURIComponent(String(body.releaseId)));
  // eslint-disable-next-line
  // @ts-ignore
  delete body.trackId;
  // eslint-disable-next-line
  // @ts-ignore
  delete body.releaseId;
  return Axios<unknown>(
    {
      url,
      method: 'DELETE',
    },
    customAxiosInstance
  );
};

export const useDeleteReleaseMutation = <Error = ApiError>(
  options?: {
    mutation?:UseMutationOptions<unknown, Error>,
    customAxiosInstance?: AxiosInstance;
  }
) => {
  const {mutation: mutationOptions, customAxiosInstance} = options ?? {};
  // eslint-disable-next-line
  // @ts-ignore
  return useMutation<unknown, Error, DeleteReleaseForQuery, unknown>((props) => {
    return  deleteReleaseMutate(props, customAxiosInstance);
  }, mutationOptions);
};


/**
 * Delete a DB software release track
 * Delete a DB software release track
 */


export const deleteTrackMutate = (
  body: DeleteTrackForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  const url = '/private/software/tracks/{trackId}'.replace(`{${'trackId'}}`, encodeURIComponent(String(body.trackId)));
  // eslint-disable-next-line
  // @ts-ignore
  delete body.trackId;
  return Axios<unknown>(
    {
      url,
      method: 'DELETE',
    },
    customAxiosInstance
  );
};

export const useDeleteTrackMutation = <Error = ApiError>(
  options?: {
    mutation?:UseMutationOptions<unknown, Error>,
    customAxiosInstance?: AxiosInstance;
  }
) => {
  const {mutation: mutationOptions, customAxiosInstance} = options ?? {};
  // eslint-disable-next-line
  // @ts-ignore
  return useMutation<unknown, Error, DeleteTrackForQuery, unknown>((props) => {
    return  deleteTrackMutate(props, customAxiosInstance);
  }, mutationOptions);
};


/**
 * List of all software releases for a track
 * List all DB software releases by track
 */

export const listReleasesOnTrackAxiosRequest = (
  requestParameters: ListReleasesOnTrackForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  return Axios<SoftwareReleaseListResponse>(
    {
      url: '/private/software/tracks/{trackId}/releases'.replace(`{${'trackId'}}`, encodeURIComponent(String(requestParameters.trackId))),
      method: 'GET',
      params: {
        limit: requestParameters['limit'],
        continuation_token: requestParameters['continuation_token'],
      }
    },
    customAxiosInstance
  );
};

export const listReleasesOnTrackQueryKey = (
  requestParametersQuery: ListReleasesOnTrackForQuery,
  pageParam = -1,
  version = 1,
) => [
  `/v${version}/private/software/tracks/{trackId}/releases`,
  pageParam,
  ...(requestParametersQuery ? [requestParametersQuery] : [])
];


export const useListReleasesOnTrackInfiniteQuery = <T = SoftwareReleaseListResponse, Error = ApiError>(
  params: ListReleasesOnTrackForQuery,
  options?: {
    query?: UseInfiniteQueryOptions<SoftwareReleaseListResponse, Error, T>;
    customAxiosInstance?: AxiosInstance;
  },
  pageParam = -1,
  version = 1,
) => {
  const queryKey = listReleasesOnTrackQueryKey(params, pageParam, version);
  const { query: queryOptions, customAxiosInstance } = options ?? {};

  const query = useInfiniteQuery<SoftwareReleaseListResponse, Error, T>(
    queryKey,
    () => listReleasesOnTrackAxiosRequest(params, customAxiosInstance),
    queryOptions
  );

  return {
    queryKey,
    ...query
  };
};

export const useListReleasesOnTrackQuery = <T = SoftwareReleaseListResponse, Error = ApiError>(
  params: ListReleasesOnTrackForQuery,
  options?: {
    query?: UseQueryOptions<SoftwareReleaseListResponse, Error, T>;
    customAxiosInstance?: AxiosInstance;
  },
  version = 1,
) => {
  const queryKey = listReleasesOnTrackQueryKey(params,  version);
  const { query: queryOptions, customAxiosInstance } = options ?? {};

  const query = useQuery<SoftwareReleaseListResponse, Error, T>(
    queryKey,
    () => listReleasesOnTrackAxiosRequest(params, customAxiosInstance),
    queryOptions
  );

  return {
    queryKey,
    ...query
  };
};



/**
 * List all DB software release tracks
 * List all DB software release tracks
 */

export const listTracksAxiosRequest = (
  requestParameters: ListTracksForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  return Axios<SoftwareReleaseTrackListPagedResponse>(
    {
      url: '/private/software/tracks',
      method: 'GET',
      params: {
        limit: requestParameters['limit'],
        continuation_token: requestParameters['continuation_token'],
      }
    },
    customAxiosInstance
  );
};

export const listTracksQueryKey = (
  requestParametersQuery: ListTracksForQuery,
  pageParam = -1,
  version = 1,
) => [
  `/v${version}/private/software/tracks`,
  pageParam,
  ...(requestParametersQuery ? [requestParametersQuery] : [])
];


export const useListTracksInfiniteQuery = <T = SoftwareReleaseTrackListPagedResponse, Error = ApiError>(
  params: ListTracksForQuery,
  options?: {
    query?: UseInfiniteQueryOptions<SoftwareReleaseTrackListPagedResponse, Error, T>;
    customAxiosInstance?: AxiosInstance;
  },
  pageParam = -1,
  version = 1,
) => {
  const queryKey = listTracksQueryKey(params, pageParam, version);
  const { query: queryOptions, customAxiosInstance } = options ?? {};

  const query = useInfiniteQuery<SoftwareReleaseTrackListPagedResponse, Error, T>(
    queryKey,
    () => listTracksAxiosRequest(params, customAxiosInstance),
    queryOptions
  );

  return {
    queryKey,
    ...query
  };
};

export const useListTracksQuery = <T = SoftwareReleaseTrackListPagedResponse, Error = ApiError>(
  params: ListTracksForQuery,
  options?: {
    query?: UseQueryOptions<SoftwareReleaseTrackListPagedResponse, Error, T>;
    customAxiosInstance?: AxiosInstance;
  },
  version = 1,
) => {
  const queryKey = listTracksQueryKey(params,  version);
  const { query: queryOptions, customAxiosInstance } = options ?? {};

  const query = useQuery<SoftwareReleaseTrackListPagedResponse, Error, T>(
    queryKey,
    () => listTracksAxiosRequest(params, customAxiosInstance),
    queryOptions
  );

  return {
    queryKey,
    ...query
  };
};



/**
 * Remove release track from account
 * Remove release track from account
 */


export const removeTrackMutate = (
  body: RemoveTrackForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  const url = '/private/accounts/{accountId}/software/tracks/{trackId}'.replace(`{${'accountId'}}`, encodeURIComponent(String(body.accountId))).replace(`{${'trackId'}}`, encodeURIComponent(String(body.trackId)));
  // eslint-disable-next-line
  // @ts-ignore
  delete body.accountId;
  // eslint-disable-next-line
  // @ts-ignore
  delete body.trackId;
  return Axios<unknown>(
    {
      url,
      method: 'DELETE',
    },
    customAxiosInstance
  );
};

export const useRemoveTrackMutation = <Error = ApiError>(
  options?: {
    mutation?:UseMutationOptions<unknown, Error>,
    customAxiosInstance?: AxiosInstance;
  }
) => {
  const {mutation: mutationOptions, customAxiosInstance} = options ?? {};
  // eslint-disable-next-line
  // @ts-ignore
  return useMutation<unknown, Error, RemoveTrackForQuery, unknown>((props) => {
    return  removeTrackMutate(props, customAxiosInstance);
  }, mutationOptions);
};


/**
 * Update a software release
 * Update a software release
 */


export const updateReleaseMutate = (
  body: UpdateReleaseForQuery,
  customAxiosInstance?: AxiosInstance
) => {
  const url = '/private/software/tracks/{trackId}/releases/{releaseId}'.replace(`{${'trackId'}}`, encodeURIComponent(String(body.trackId))).replace(`{${'releaseId'}}`, encodeURIComponent(String(body.releaseId)));
  // eslint-disable-next-line
  // @ts-ignore
  delete body.trackId;
  // eslint-disable-next-line
  // @ts-ignore
  delete body.releaseId;
  return Axios<SoftwareReleaseResponse>(
    {
      url,
      method: 'PUT',
      data: body.SoftwareReleaseSpec
    },
    customAxiosInstance
  );
};

export const useUpdateReleaseMutation = <Error = ApiError>(
  options?: {
    mutation?:UseMutationOptions<SoftwareReleaseResponse, Error>,
    customAxiosInstance?: AxiosInstance;
  }
) => {
  const {mutation: mutationOptions, customAxiosInstance} = options ?? {};
  // eslint-disable-next-line
  // @ts-ignore
  return useMutation<SoftwareReleaseResponse, Error, UpdateReleaseForQuery, unknown>((props) => {
    return  updateReleaseMutate(props, customAxiosInstance);
  }, mutationOptions);
};






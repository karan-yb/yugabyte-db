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


// eslint-disable-next-line no-duplicate-imports
import type { InviteUserSpec } from './InviteUserSpec';
// eslint-disable-next-line no-duplicate-imports
import type { UserInfo } from './UserInfo';


/**
 * Invite User Data
 * @export
 * @interface InviteUserData
 */
export interface InviteUserData  {
  /**
   * 
   * @type {InviteUserSpec}
   * @memberof InviteUserData
   */
  spec?: InviteUserSpec;
  /**
   * 
   * @type {UserInfo}
   * @memberof InviteUserData
   */
  info?: UserInfo;
}




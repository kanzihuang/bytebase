/* eslint-disable */
import type { CallContext, CallOptions } from "nice-grpc-common";
import * as _m0 from "protobufjs/minimal";
import { FieldMask } from "../google/protobuf/field_mask";
import { Timestamp } from "../google/protobuf/timestamp";

export const protobufPackage = "bytebase.v1";

export enum ReviewStatus {
  REVIEW_STATUS_UNSPECIFIED = 0,
  OPEN = 1,
  DONE = 2,
  CANCELED = 3,
  UNRECOGNIZED = -1,
}

export function reviewStatusFromJSON(object: any): ReviewStatus {
  switch (object) {
    case 0:
    case "REVIEW_STATUS_UNSPECIFIED":
      return ReviewStatus.REVIEW_STATUS_UNSPECIFIED;
    case 1:
    case "OPEN":
      return ReviewStatus.OPEN;
    case 2:
    case "DONE":
      return ReviewStatus.DONE;
    case 3:
    case "CANCELED":
      return ReviewStatus.CANCELED;
    case -1:
    case "UNRECOGNIZED":
    default:
      return ReviewStatus.UNRECOGNIZED;
  }
}

export function reviewStatusToJSON(object: ReviewStatus): string {
  switch (object) {
    case ReviewStatus.REVIEW_STATUS_UNSPECIFIED:
      return "REVIEW_STATUS_UNSPECIFIED";
    case ReviewStatus.OPEN:
      return "OPEN";
    case ReviewStatus.DONE:
      return "DONE";
    case ReviewStatus.CANCELED:
      return "CANCELED";
    case ReviewStatus.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface GetIssueRequest {
  /**
   * The name of the review to retrieve.
   * Format: projects/{project}/reviews/{review}
   */
  name: string;
  force: boolean;
}

export interface CreateIssueRequest {
  /**
   * The parent, which owns this collection of reviews.
   * Format: projects/{project}
   */
  parent: string;
  /** The review to create. */
  review?: Review;
}

export interface ListIssuesRequest {
  /**
   * The parent, which owns this collection of reviews.
   * Format: projects/{project}
   * Use "projects/-" to list all reviews from all projects.
   */
  parent: string;
  /**
   * The maximum number of reviews to return. The service may return fewer than
   * this value.
   * If unspecified, at most 50 reviews will be returned.
   * The maximum value is 1000; values above 1000 will be coerced to 1000.
   */
  pageSize: number;
  /**
   * A page token, received from a previous `ListIssues` call.
   * Provide this to retrieve the subsequent page.
   *
   * When paginating, all other parameters provided to `ListIssues` must match
   * the call that provided the page token.
   */
  pageToken: string;
}

export interface ListIssuesResponse {
  /** The reviews from the specified request. */
  reviews: Review[];
  /**
   * A token, which can be sent as `page_token` to retrieve the next page.
   * If this field is omitted, there are no subsequent pages.
   */
  nextPageToken: string;
}

export interface UpdateIssueRequest {
  /**
   * The review to update.
   *
   * The review's `name` field is used to identify the review to update.
   * Format: projects/{project}/reviews/{review}
   */
  review?: Review;
  /** The list of fields to update. */
  updateMask?: string[];
}

export interface BatchUpdateIssuesRequest {
  /**
   * The parent resource shared by all reviews being updated.
   * Format: projects/{project}
   * If the operation spans parents, a dash (-) may be accepted as a wildcard.
   * We only support updating the status of databases for now.
   */
  parent: string;
  /**
   * The request message specifying the resources to update.
   * A maximum of 1000 databases can be modified in a batch.
   */
  requests: UpdateIssueRequest[];
}

export interface BatchUpdateIssuesResponse {
  /** Reviews updated. */
  reviews: Review[];
}

export interface ApproveReviewRequest {
  /**
   * The name of the review to add an approver.
   * Format: projects/{project}/reviews/{review}
   */
  name: string;
  comment: string;
}

export interface RejectReviewRequest {
  /**
   * The name of the review to add an rejecting reviewer.
   * Format: projects/{project}/reviews/{review}
   */
  name: string;
  comment: string;
}

export interface RequestReviewRequest {
  /**
   * The name of the review to request a review.
   * Format: projects/{project}/reviews/{review}
   */
  name: string;
  comment: string;
}

export interface Review {
  /**
   * The name of the review.
   * `review` is a system generated ID.
   * Format: projects/{project}/reviews/{review}
   */
  name: string;
  /** The system-assigned, unique identifier for a resource. */
  uid: string;
  title: string;
  /**
   * The plan associated with the review.
   * Can be empty.
   * Format: projects/{project}/plans/{plan}
   */
  plan: string;
  /**
   * The rollout associated with the review.
   * Can be empty.
   * Format: projects/{project}/rollouts/{rollout}
   */
  rollout: string;
  description: string;
  status: ReviewStatus;
  /** Format: users/hello@world.com */
  assignee: string;
  assigneeAttention: boolean;
  approvalTemplates: ApprovalTemplate[];
  approvers: Review_Approver[];
  /**
   * If the value is `false`, it means that the backend is still finding matching approval templates.
   * If `true`, approval_templates & approvers & approval_finding_error are available.
   */
  approvalFindingDone: boolean;
  approvalFindingError: string;
  /**
   * The subscribers.
   * Format: users/hello@world.com
   */
  subscribers: string[];
  /** Format: users/hello@world.com */
  creator: string;
  createTime?: Date;
  updateTime?: Date;
}

export interface Review_Approver {
  /** The new status. */
  status: Review_Approver_Status;
  /** Format: users/hello@world.com */
  principal: string;
}

export enum Review_Approver_Status {
  STATUS_UNSPECIFIED = 0,
  PENDING = 1,
  APPROVED = 2,
  REJECTED = 3,
  UNRECOGNIZED = -1,
}

export function review_Approver_StatusFromJSON(object: any): Review_Approver_Status {
  switch (object) {
    case 0:
    case "STATUS_UNSPECIFIED":
      return Review_Approver_Status.STATUS_UNSPECIFIED;
    case 1:
    case "PENDING":
      return Review_Approver_Status.PENDING;
    case 2:
    case "APPROVED":
      return Review_Approver_Status.APPROVED;
    case 3:
    case "REJECTED":
      return Review_Approver_Status.REJECTED;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Review_Approver_Status.UNRECOGNIZED;
  }
}

export function review_Approver_StatusToJSON(object: Review_Approver_Status): string {
  switch (object) {
    case Review_Approver_Status.STATUS_UNSPECIFIED:
      return "STATUS_UNSPECIFIED";
    case Review_Approver_Status.PENDING:
      return "PENDING";
    case Review_Approver_Status.APPROVED:
      return "APPROVED";
    case Review_Approver_Status.REJECTED:
      return "REJECTED";
    case Review_Approver_Status.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface ApprovalTemplate {
  flow?: ApprovalFlow;
  title: string;
  description: string;
  /**
   * The name of the creator in users/{email} format.
   * TODO: we should mark it as OUTPUT_ONLY, but currently the frontend will post the approval setting with creator.
   */
  creator: string;
}

export interface ApprovalFlow {
  steps: ApprovalStep[];
}

export interface ApprovalStep {
  type: ApprovalStep_Type;
  nodes: ApprovalNode[];
}

/**
 * Type of the ApprovalStep
 * ALL means every node must be approved to proceed.
 * ANY means approving any node will proceed.
 */
export enum ApprovalStep_Type {
  TYPE_UNSPECIFIED = 0,
  ALL = 1,
  ANY = 2,
  UNRECOGNIZED = -1,
}

export function approvalStep_TypeFromJSON(object: any): ApprovalStep_Type {
  switch (object) {
    case 0:
    case "TYPE_UNSPECIFIED":
      return ApprovalStep_Type.TYPE_UNSPECIFIED;
    case 1:
    case "ALL":
      return ApprovalStep_Type.ALL;
    case 2:
    case "ANY":
      return ApprovalStep_Type.ANY;
    case -1:
    case "UNRECOGNIZED":
    default:
      return ApprovalStep_Type.UNRECOGNIZED;
  }
}

export function approvalStep_TypeToJSON(object: ApprovalStep_Type): string {
  switch (object) {
    case ApprovalStep_Type.TYPE_UNSPECIFIED:
      return "TYPE_UNSPECIFIED";
    case ApprovalStep_Type.ALL:
      return "ALL";
    case ApprovalStep_Type.ANY:
      return "ANY";
    case ApprovalStep_Type.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface ApprovalNode {
  type: ApprovalNode_Type;
  groupValue?:
    | ApprovalNode_GroupValue
    | undefined;
  /** Format: roles/{role} */
  role?: string | undefined;
  externalNodeId?: string | undefined;
}

/**
 * Type of the ApprovalNode.
 * type determines who should approve this node.
 * ANY_IN_GROUP means the ApprovalNode can be approved by an user from our predefined user group.
 * See GroupValue below for the predefined user groups.
 */
export enum ApprovalNode_Type {
  TYPE_UNSPECIFIED = 0,
  ANY_IN_GROUP = 1,
  UNRECOGNIZED = -1,
}

export function approvalNode_TypeFromJSON(object: any): ApprovalNode_Type {
  switch (object) {
    case 0:
    case "TYPE_UNSPECIFIED":
      return ApprovalNode_Type.TYPE_UNSPECIFIED;
    case 1:
    case "ANY_IN_GROUP":
      return ApprovalNode_Type.ANY_IN_GROUP;
    case -1:
    case "UNRECOGNIZED":
    default:
      return ApprovalNode_Type.UNRECOGNIZED;
  }
}

export function approvalNode_TypeToJSON(object: ApprovalNode_Type): string {
  switch (object) {
    case ApprovalNode_Type.TYPE_UNSPECIFIED:
      return "TYPE_UNSPECIFIED";
    case ApprovalNode_Type.ANY_IN_GROUP:
      return "ANY_IN_GROUP";
    case ApprovalNode_Type.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

/**
 * The predefined user groups are:
 * - WORKSPACE_OWNER
 * - WORKSPACE_DBA
 * - PROJECT_OWNER
 * - PROJECT_MEMBER
 */
export enum ApprovalNode_GroupValue {
  GROUP_VALUE_UNSPECIFILED = 0,
  WORKSPACE_OWNER = 1,
  WORKSPACE_DBA = 2,
  PROJECT_OWNER = 3,
  PROJECT_MEMBER = 4,
  UNRECOGNIZED = -1,
}

export function approvalNode_GroupValueFromJSON(object: any): ApprovalNode_GroupValue {
  switch (object) {
    case 0:
    case "GROUP_VALUE_UNSPECIFILED":
      return ApprovalNode_GroupValue.GROUP_VALUE_UNSPECIFILED;
    case 1:
    case "WORKSPACE_OWNER":
      return ApprovalNode_GroupValue.WORKSPACE_OWNER;
    case 2:
    case "WORKSPACE_DBA":
      return ApprovalNode_GroupValue.WORKSPACE_DBA;
    case 3:
    case "PROJECT_OWNER":
      return ApprovalNode_GroupValue.PROJECT_OWNER;
    case 4:
    case "PROJECT_MEMBER":
      return ApprovalNode_GroupValue.PROJECT_MEMBER;
    case -1:
    case "UNRECOGNIZED":
    default:
      return ApprovalNode_GroupValue.UNRECOGNIZED;
  }
}

export function approvalNode_GroupValueToJSON(object: ApprovalNode_GroupValue): string {
  switch (object) {
    case ApprovalNode_GroupValue.GROUP_VALUE_UNSPECIFILED:
      return "GROUP_VALUE_UNSPECIFILED";
    case ApprovalNode_GroupValue.WORKSPACE_OWNER:
      return "WORKSPACE_OWNER";
    case ApprovalNode_GroupValue.WORKSPACE_DBA:
      return "WORKSPACE_DBA";
    case ApprovalNode_GroupValue.PROJECT_OWNER:
      return "PROJECT_OWNER";
    case ApprovalNode_GroupValue.PROJECT_MEMBER:
      return "PROJECT_MEMBER";
    case ApprovalNode_GroupValue.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface CreateIssueCommentRequest {
  /**
   * The review name
   * Format: projects/{project}/reviews/{review}
   */
  parent: string;
  reviewComment?: ReviewComment;
}

export interface UpdateIssueCommentRequest {
  /**
   * The review name
   * Format: projects/{project}/reviews/{review}
   */
  parent: string;
  reviewComment?: ReviewComment;
  /** The list of fields to update. */
  updateMask?: string[];
}

export interface ReviewComment {
  uid: string;
  comment: string;
  /** TODO: use struct message instead. */
  payload: string;
  createTime?: Date;
  updateTime?: Date;
}

function createBaseGetIssueRequest(): GetIssueRequest {
  return { name: "", force: false };
}

export const GetIssueRequest = {
  encode(message: GetIssueRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.force === true) {
      writer.uint32(16).bool(message.force);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): GetIssueRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseGetIssueRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.name = reader.string();
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.force = reader.bool();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): GetIssueRequest {
    return {
      name: isSet(object.name) ? String(object.name) : "",
      force: isSet(object.force) ? Boolean(object.force) : false,
    };
  },

  toJSON(message: GetIssueRequest): unknown {
    const obj: any = {};
    message.name !== undefined && (obj.name = message.name);
    message.force !== undefined && (obj.force = message.force);
    return obj;
  },

  create(base?: DeepPartial<GetIssueRequest>): GetIssueRequest {
    return GetIssueRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<GetIssueRequest>): GetIssueRequest {
    const message = createBaseGetIssueRequest();
    message.name = object.name ?? "";
    message.force = object.force ?? false;
    return message;
  },
};

function createBaseCreateIssueRequest(): CreateIssueRequest {
  return { parent: "", review: undefined };
}

export const CreateIssueRequest = {
  encode(message: CreateIssueRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.parent !== "") {
      writer.uint32(10).string(message.parent);
    }
    if (message.review !== undefined) {
      Review.encode(message.review, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CreateIssueRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCreateIssueRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.parent = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.review = Review.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): CreateIssueRequest {
    return {
      parent: isSet(object.parent) ? String(object.parent) : "",
      review: isSet(object.review) ? Review.fromJSON(object.review) : undefined,
    };
  },

  toJSON(message: CreateIssueRequest): unknown {
    const obj: any = {};
    message.parent !== undefined && (obj.parent = message.parent);
    message.review !== undefined && (obj.review = message.review ? Review.toJSON(message.review) : undefined);
    return obj;
  },

  create(base?: DeepPartial<CreateIssueRequest>): CreateIssueRequest {
    return CreateIssueRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<CreateIssueRequest>): CreateIssueRequest {
    const message = createBaseCreateIssueRequest();
    message.parent = object.parent ?? "";
    message.review = (object.review !== undefined && object.review !== null)
      ? Review.fromPartial(object.review)
      : undefined;
    return message;
  },
};

function createBaseListIssuesRequest(): ListIssuesRequest {
  return { parent: "", pageSize: 0, pageToken: "" };
}

export const ListIssuesRequest = {
  encode(message: ListIssuesRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.parent !== "") {
      writer.uint32(10).string(message.parent);
    }
    if (message.pageSize !== 0) {
      writer.uint32(16).int32(message.pageSize);
    }
    if (message.pageToken !== "") {
      writer.uint32(26).string(message.pageToken);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ListIssuesRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseListIssuesRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.parent = reader.string();
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.pageSize = reader.int32();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.pageToken = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ListIssuesRequest {
    return {
      parent: isSet(object.parent) ? String(object.parent) : "",
      pageSize: isSet(object.pageSize) ? Number(object.pageSize) : 0,
      pageToken: isSet(object.pageToken) ? String(object.pageToken) : "",
    };
  },

  toJSON(message: ListIssuesRequest): unknown {
    const obj: any = {};
    message.parent !== undefined && (obj.parent = message.parent);
    message.pageSize !== undefined && (obj.pageSize = Math.round(message.pageSize));
    message.pageToken !== undefined && (obj.pageToken = message.pageToken);
    return obj;
  },

  create(base?: DeepPartial<ListIssuesRequest>): ListIssuesRequest {
    return ListIssuesRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ListIssuesRequest>): ListIssuesRequest {
    const message = createBaseListIssuesRequest();
    message.parent = object.parent ?? "";
    message.pageSize = object.pageSize ?? 0;
    message.pageToken = object.pageToken ?? "";
    return message;
  },
};

function createBaseListIssuesResponse(): ListIssuesResponse {
  return { reviews: [], nextPageToken: "" };
}

export const ListIssuesResponse = {
  encode(message: ListIssuesResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    for (const v of message.reviews) {
      Review.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    if (message.nextPageToken !== "") {
      writer.uint32(18).string(message.nextPageToken);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ListIssuesResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseListIssuesResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.reviews.push(Review.decode(reader, reader.uint32()));
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.nextPageToken = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ListIssuesResponse {
    return {
      reviews: Array.isArray(object?.reviews) ? object.reviews.map((e: any) => Review.fromJSON(e)) : [],
      nextPageToken: isSet(object.nextPageToken) ? String(object.nextPageToken) : "",
    };
  },

  toJSON(message: ListIssuesResponse): unknown {
    const obj: any = {};
    if (message.reviews) {
      obj.reviews = message.reviews.map((e) => e ? Review.toJSON(e) : undefined);
    } else {
      obj.reviews = [];
    }
    message.nextPageToken !== undefined && (obj.nextPageToken = message.nextPageToken);
    return obj;
  },

  create(base?: DeepPartial<ListIssuesResponse>): ListIssuesResponse {
    return ListIssuesResponse.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ListIssuesResponse>): ListIssuesResponse {
    const message = createBaseListIssuesResponse();
    message.reviews = object.reviews?.map((e) => Review.fromPartial(e)) || [];
    message.nextPageToken = object.nextPageToken ?? "";
    return message;
  },
};

function createBaseUpdateIssueRequest(): UpdateIssueRequest {
  return { review: undefined, updateMask: undefined };
}

export const UpdateIssueRequest = {
  encode(message: UpdateIssueRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.review !== undefined) {
      Review.encode(message.review, writer.uint32(10).fork()).ldelim();
    }
    if (message.updateMask !== undefined) {
      FieldMask.encode(FieldMask.wrap(message.updateMask), writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): UpdateIssueRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseUpdateIssueRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.review = Review.decode(reader, reader.uint32());
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.updateMask = FieldMask.unwrap(FieldMask.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): UpdateIssueRequest {
    return {
      review: isSet(object.review) ? Review.fromJSON(object.review) : undefined,
      updateMask: isSet(object.updateMask) ? FieldMask.unwrap(FieldMask.fromJSON(object.updateMask)) : undefined,
    };
  },

  toJSON(message: UpdateIssueRequest): unknown {
    const obj: any = {};
    message.review !== undefined && (obj.review = message.review ? Review.toJSON(message.review) : undefined);
    message.updateMask !== undefined && (obj.updateMask = FieldMask.toJSON(FieldMask.wrap(message.updateMask)));
    return obj;
  },

  create(base?: DeepPartial<UpdateIssueRequest>): UpdateIssueRequest {
    return UpdateIssueRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<UpdateIssueRequest>): UpdateIssueRequest {
    const message = createBaseUpdateIssueRequest();
    message.review = (object.review !== undefined && object.review !== null)
      ? Review.fromPartial(object.review)
      : undefined;
    message.updateMask = object.updateMask ?? undefined;
    return message;
  },
};

function createBaseBatchUpdateIssuesRequest(): BatchUpdateIssuesRequest {
  return { parent: "", requests: [] };
}

export const BatchUpdateIssuesRequest = {
  encode(message: BatchUpdateIssuesRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.parent !== "") {
      writer.uint32(10).string(message.parent);
    }
    for (const v of message.requests) {
      UpdateIssueRequest.encode(v!, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): BatchUpdateIssuesRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBatchUpdateIssuesRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.parent = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.requests.push(UpdateIssueRequest.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): BatchUpdateIssuesRequest {
    return {
      parent: isSet(object.parent) ? String(object.parent) : "",
      requests: Array.isArray(object?.requests) ? object.requests.map((e: any) => UpdateIssueRequest.fromJSON(e)) : [],
    };
  },

  toJSON(message: BatchUpdateIssuesRequest): unknown {
    const obj: any = {};
    message.parent !== undefined && (obj.parent = message.parent);
    if (message.requests) {
      obj.requests = message.requests.map((e) => e ? UpdateIssueRequest.toJSON(e) : undefined);
    } else {
      obj.requests = [];
    }
    return obj;
  },

  create(base?: DeepPartial<BatchUpdateIssuesRequest>): BatchUpdateIssuesRequest {
    return BatchUpdateIssuesRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<BatchUpdateIssuesRequest>): BatchUpdateIssuesRequest {
    const message = createBaseBatchUpdateIssuesRequest();
    message.parent = object.parent ?? "";
    message.requests = object.requests?.map((e) => UpdateIssueRequest.fromPartial(e)) || [];
    return message;
  },
};

function createBaseBatchUpdateIssuesResponse(): BatchUpdateIssuesResponse {
  return { reviews: [] };
}

export const BatchUpdateIssuesResponse = {
  encode(message: BatchUpdateIssuesResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    for (const v of message.reviews) {
      Review.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): BatchUpdateIssuesResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBatchUpdateIssuesResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.reviews.push(Review.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): BatchUpdateIssuesResponse {
    return { reviews: Array.isArray(object?.reviews) ? object.reviews.map((e: any) => Review.fromJSON(e)) : [] };
  },

  toJSON(message: BatchUpdateIssuesResponse): unknown {
    const obj: any = {};
    if (message.reviews) {
      obj.reviews = message.reviews.map((e) => e ? Review.toJSON(e) : undefined);
    } else {
      obj.reviews = [];
    }
    return obj;
  },

  create(base?: DeepPartial<BatchUpdateIssuesResponse>): BatchUpdateIssuesResponse {
    return BatchUpdateIssuesResponse.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<BatchUpdateIssuesResponse>): BatchUpdateIssuesResponse {
    const message = createBaseBatchUpdateIssuesResponse();
    message.reviews = object.reviews?.map((e) => Review.fromPartial(e)) || [];
    return message;
  },
};

function createBaseApproveReviewRequest(): ApproveReviewRequest {
  return { name: "", comment: "" };
}

export const ApproveReviewRequest = {
  encode(message: ApproveReviewRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.comment !== "") {
      writer.uint32(18).string(message.comment);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ApproveReviewRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseApproveReviewRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.name = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.comment = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ApproveReviewRequest {
    return {
      name: isSet(object.name) ? String(object.name) : "",
      comment: isSet(object.comment) ? String(object.comment) : "",
    };
  },

  toJSON(message: ApproveReviewRequest): unknown {
    const obj: any = {};
    message.name !== undefined && (obj.name = message.name);
    message.comment !== undefined && (obj.comment = message.comment);
    return obj;
  },

  create(base?: DeepPartial<ApproveReviewRequest>): ApproveReviewRequest {
    return ApproveReviewRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ApproveReviewRequest>): ApproveReviewRequest {
    const message = createBaseApproveReviewRequest();
    message.name = object.name ?? "";
    message.comment = object.comment ?? "";
    return message;
  },
};

function createBaseRejectReviewRequest(): RejectReviewRequest {
  return { name: "", comment: "" };
}

export const RejectReviewRequest = {
  encode(message: RejectReviewRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.comment !== "") {
      writer.uint32(18).string(message.comment);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): RejectReviewRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseRejectReviewRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.name = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.comment = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): RejectReviewRequest {
    return {
      name: isSet(object.name) ? String(object.name) : "",
      comment: isSet(object.comment) ? String(object.comment) : "",
    };
  },

  toJSON(message: RejectReviewRequest): unknown {
    const obj: any = {};
    message.name !== undefined && (obj.name = message.name);
    message.comment !== undefined && (obj.comment = message.comment);
    return obj;
  },

  create(base?: DeepPartial<RejectReviewRequest>): RejectReviewRequest {
    return RejectReviewRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<RejectReviewRequest>): RejectReviewRequest {
    const message = createBaseRejectReviewRequest();
    message.name = object.name ?? "";
    message.comment = object.comment ?? "";
    return message;
  },
};

function createBaseRequestReviewRequest(): RequestReviewRequest {
  return { name: "", comment: "" };
}

export const RequestReviewRequest = {
  encode(message: RequestReviewRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.comment !== "") {
      writer.uint32(18).string(message.comment);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): RequestReviewRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseRequestReviewRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.name = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.comment = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): RequestReviewRequest {
    return {
      name: isSet(object.name) ? String(object.name) : "",
      comment: isSet(object.comment) ? String(object.comment) : "",
    };
  },

  toJSON(message: RequestReviewRequest): unknown {
    const obj: any = {};
    message.name !== undefined && (obj.name = message.name);
    message.comment !== undefined && (obj.comment = message.comment);
    return obj;
  },

  create(base?: DeepPartial<RequestReviewRequest>): RequestReviewRequest {
    return RequestReviewRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<RequestReviewRequest>): RequestReviewRequest {
    const message = createBaseRequestReviewRequest();
    message.name = object.name ?? "";
    message.comment = object.comment ?? "";
    return message;
  },
};

function createBaseReview(): Review {
  return {
    name: "",
    uid: "",
    title: "",
    plan: "",
    rollout: "",
    description: "",
    status: 0,
    assignee: "",
    assigneeAttention: false,
    approvalTemplates: [],
    approvers: [],
    approvalFindingDone: false,
    approvalFindingError: "",
    subscribers: [],
    creator: "",
    createTime: undefined,
    updateTime: undefined,
  };
}

export const Review = {
  encode(message: Review, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.uid !== "") {
      writer.uint32(18).string(message.uid);
    }
    if (message.title !== "") {
      writer.uint32(26).string(message.title);
    }
    if (message.plan !== "") {
      writer.uint32(130).string(message.plan);
    }
    if (message.rollout !== "") {
      writer.uint32(138).string(message.rollout);
    }
    if (message.description !== "") {
      writer.uint32(34).string(message.description);
    }
    if (message.status !== 0) {
      writer.uint32(40).int32(message.status);
    }
    if (message.assignee !== "") {
      writer.uint32(50).string(message.assignee);
    }
    if (message.assigneeAttention === true) {
      writer.uint32(56).bool(message.assigneeAttention);
    }
    for (const v of message.approvalTemplates) {
      ApprovalTemplate.encode(v!, writer.uint32(66).fork()).ldelim();
    }
    for (const v of message.approvers) {
      Review_Approver.encode(v!, writer.uint32(74).fork()).ldelim();
    }
    if (message.approvalFindingDone === true) {
      writer.uint32(80).bool(message.approvalFindingDone);
    }
    if (message.approvalFindingError !== "") {
      writer.uint32(90).string(message.approvalFindingError);
    }
    for (const v of message.subscribers) {
      writer.uint32(98).string(v!);
    }
    if (message.creator !== "") {
      writer.uint32(106).string(message.creator);
    }
    if (message.createTime !== undefined) {
      Timestamp.encode(toTimestamp(message.createTime), writer.uint32(114).fork()).ldelim();
    }
    if (message.updateTime !== undefined) {
      Timestamp.encode(toTimestamp(message.updateTime), writer.uint32(122).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): Review {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseReview();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.name = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.uid = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.title = reader.string();
          continue;
        case 16:
          if (tag !== 130) {
            break;
          }

          message.plan = reader.string();
          continue;
        case 17:
          if (tag !== 138) {
            break;
          }

          message.rollout = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.description = reader.string();
          continue;
        case 5:
          if (tag !== 40) {
            break;
          }

          message.status = reader.int32() as any;
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.assignee = reader.string();
          continue;
        case 7:
          if (tag !== 56) {
            break;
          }

          message.assigneeAttention = reader.bool();
          continue;
        case 8:
          if (tag !== 66) {
            break;
          }

          message.approvalTemplates.push(ApprovalTemplate.decode(reader, reader.uint32()));
          continue;
        case 9:
          if (tag !== 74) {
            break;
          }

          message.approvers.push(Review_Approver.decode(reader, reader.uint32()));
          continue;
        case 10:
          if (tag !== 80) {
            break;
          }

          message.approvalFindingDone = reader.bool();
          continue;
        case 11:
          if (tag !== 90) {
            break;
          }

          message.approvalFindingError = reader.string();
          continue;
        case 12:
          if (tag !== 98) {
            break;
          }

          message.subscribers.push(reader.string());
          continue;
        case 13:
          if (tag !== 106) {
            break;
          }

          message.creator = reader.string();
          continue;
        case 14:
          if (tag !== 114) {
            break;
          }

          message.createTime = fromTimestamp(Timestamp.decode(reader, reader.uint32()));
          continue;
        case 15:
          if (tag !== 122) {
            break;
          }

          message.updateTime = fromTimestamp(Timestamp.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): Review {
    return {
      name: isSet(object.name) ? String(object.name) : "",
      uid: isSet(object.uid) ? String(object.uid) : "",
      title: isSet(object.title) ? String(object.title) : "",
      plan: isSet(object.plan) ? String(object.plan) : "",
      rollout: isSet(object.rollout) ? String(object.rollout) : "",
      description: isSet(object.description) ? String(object.description) : "",
      status: isSet(object.status) ? reviewStatusFromJSON(object.status) : 0,
      assignee: isSet(object.assignee) ? String(object.assignee) : "",
      assigneeAttention: isSet(object.assigneeAttention) ? Boolean(object.assigneeAttention) : false,
      approvalTemplates: Array.isArray(object?.approvalTemplates)
        ? object.approvalTemplates.map((e: any) => ApprovalTemplate.fromJSON(e))
        : [],
      approvers: Array.isArray(object?.approvers) ? object.approvers.map((e: any) => Review_Approver.fromJSON(e)) : [],
      approvalFindingDone: isSet(object.approvalFindingDone) ? Boolean(object.approvalFindingDone) : false,
      approvalFindingError: isSet(object.approvalFindingError) ? String(object.approvalFindingError) : "",
      subscribers: Array.isArray(object?.subscribers) ? object.subscribers.map((e: any) => String(e)) : [],
      creator: isSet(object.creator) ? String(object.creator) : "",
      createTime: isSet(object.createTime) ? fromJsonTimestamp(object.createTime) : undefined,
      updateTime: isSet(object.updateTime) ? fromJsonTimestamp(object.updateTime) : undefined,
    };
  },

  toJSON(message: Review): unknown {
    const obj: any = {};
    message.name !== undefined && (obj.name = message.name);
    message.uid !== undefined && (obj.uid = message.uid);
    message.title !== undefined && (obj.title = message.title);
    message.plan !== undefined && (obj.plan = message.plan);
    message.rollout !== undefined && (obj.rollout = message.rollout);
    message.description !== undefined && (obj.description = message.description);
    message.status !== undefined && (obj.status = reviewStatusToJSON(message.status));
    message.assignee !== undefined && (obj.assignee = message.assignee);
    message.assigneeAttention !== undefined && (obj.assigneeAttention = message.assigneeAttention);
    if (message.approvalTemplates) {
      obj.approvalTemplates = message.approvalTemplates.map((e) => e ? ApprovalTemplate.toJSON(e) : undefined);
    } else {
      obj.approvalTemplates = [];
    }
    if (message.approvers) {
      obj.approvers = message.approvers.map((e) => e ? Review_Approver.toJSON(e) : undefined);
    } else {
      obj.approvers = [];
    }
    message.approvalFindingDone !== undefined && (obj.approvalFindingDone = message.approvalFindingDone);
    message.approvalFindingError !== undefined && (obj.approvalFindingError = message.approvalFindingError);
    if (message.subscribers) {
      obj.subscribers = message.subscribers.map((e) => e);
    } else {
      obj.subscribers = [];
    }
    message.creator !== undefined && (obj.creator = message.creator);
    message.createTime !== undefined && (obj.createTime = message.createTime.toISOString());
    message.updateTime !== undefined && (obj.updateTime = message.updateTime.toISOString());
    return obj;
  },

  create(base?: DeepPartial<Review>): Review {
    return Review.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<Review>): Review {
    const message = createBaseReview();
    message.name = object.name ?? "";
    message.uid = object.uid ?? "";
    message.title = object.title ?? "";
    message.plan = object.plan ?? "";
    message.rollout = object.rollout ?? "";
    message.description = object.description ?? "";
    message.status = object.status ?? 0;
    message.assignee = object.assignee ?? "";
    message.assigneeAttention = object.assigneeAttention ?? false;
    message.approvalTemplates = object.approvalTemplates?.map((e) => ApprovalTemplate.fromPartial(e)) || [];
    message.approvers = object.approvers?.map((e) => Review_Approver.fromPartial(e)) || [];
    message.approvalFindingDone = object.approvalFindingDone ?? false;
    message.approvalFindingError = object.approvalFindingError ?? "";
    message.subscribers = object.subscribers?.map((e) => e) || [];
    message.creator = object.creator ?? "";
    message.createTime = object.createTime ?? undefined;
    message.updateTime = object.updateTime ?? undefined;
    return message;
  },
};

function createBaseReview_Approver(): Review_Approver {
  return { status: 0, principal: "" };
}

export const Review_Approver = {
  encode(message: Review_Approver, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.status !== 0) {
      writer.uint32(8).int32(message.status);
    }
    if (message.principal !== "") {
      writer.uint32(18).string(message.principal);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): Review_Approver {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseReview_Approver();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.status = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.principal = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): Review_Approver {
    return {
      status: isSet(object.status) ? review_Approver_StatusFromJSON(object.status) : 0,
      principal: isSet(object.principal) ? String(object.principal) : "",
    };
  },

  toJSON(message: Review_Approver): unknown {
    const obj: any = {};
    message.status !== undefined && (obj.status = review_Approver_StatusToJSON(message.status));
    message.principal !== undefined && (obj.principal = message.principal);
    return obj;
  },

  create(base?: DeepPartial<Review_Approver>): Review_Approver {
    return Review_Approver.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<Review_Approver>): Review_Approver {
    const message = createBaseReview_Approver();
    message.status = object.status ?? 0;
    message.principal = object.principal ?? "";
    return message;
  },
};

function createBaseApprovalTemplate(): ApprovalTemplate {
  return { flow: undefined, title: "", description: "", creator: "" };
}

export const ApprovalTemplate = {
  encode(message: ApprovalTemplate, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.flow !== undefined) {
      ApprovalFlow.encode(message.flow, writer.uint32(10).fork()).ldelim();
    }
    if (message.title !== "") {
      writer.uint32(18).string(message.title);
    }
    if (message.description !== "") {
      writer.uint32(26).string(message.description);
    }
    if (message.creator !== "") {
      writer.uint32(34).string(message.creator);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ApprovalTemplate {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseApprovalTemplate();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.flow = ApprovalFlow.decode(reader, reader.uint32());
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.title = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.description = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.creator = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ApprovalTemplate {
    return {
      flow: isSet(object.flow) ? ApprovalFlow.fromJSON(object.flow) : undefined,
      title: isSet(object.title) ? String(object.title) : "",
      description: isSet(object.description) ? String(object.description) : "",
      creator: isSet(object.creator) ? String(object.creator) : "",
    };
  },

  toJSON(message: ApprovalTemplate): unknown {
    const obj: any = {};
    message.flow !== undefined && (obj.flow = message.flow ? ApprovalFlow.toJSON(message.flow) : undefined);
    message.title !== undefined && (obj.title = message.title);
    message.description !== undefined && (obj.description = message.description);
    message.creator !== undefined && (obj.creator = message.creator);
    return obj;
  },

  create(base?: DeepPartial<ApprovalTemplate>): ApprovalTemplate {
    return ApprovalTemplate.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ApprovalTemplate>): ApprovalTemplate {
    const message = createBaseApprovalTemplate();
    message.flow = (object.flow !== undefined && object.flow !== null)
      ? ApprovalFlow.fromPartial(object.flow)
      : undefined;
    message.title = object.title ?? "";
    message.description = object.description ?? "";
    message.creator = object.creator ?? "";
    return message;
  },
};

function createBaseApprovalFlow(): ApprovalFlow {
  return { steps: [] };
}

export const ApprovalFlow = {
  encode(message: ApprovalFlow, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    for (const v of message.steps) {
      ApprovalStep.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ApprovalFlow {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseApprovalFlow();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.steps.push(ApprovalStep.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ApprovalFlow {
    return { steps: Array.isArray(object?.steps) ? object.steps.map((e: any) => ApprovalStep.fromJSON(e)) : [] };
  },

  toJSON(message: ApprovalFlow): unknown {
    const obj: any = {};
    if (message.steps) {
      obj.steps = message.steps.map((e) => e ? ApprovalStep.toJSON(e) : undefined);
    } else {
      obj.steps = [];
    }
    return obj;
  },

  create(base?: DeepPartial<ApprovalFlow>): ApprovalFlow {
    return ApprovalFlow.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ApprovalFlow>): ApprovalFlow {
    const message = createBaseApprovalFlow();
    message.steps = object.steps?.map((e) => ApprovalStep.fromPartial(e)) || [];
    return message;
  },
};

function createBaseApprovalStep(): ApprovalStep {
  return { type: 0, nodes: [] };
}

export const ApprovalStep = {
  encode(message: ApprovalStep, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    for (const v of message.nodes) {
      ApprovalNode.encode(v!, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ApprovalStep {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseApprovalStep();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.type = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.nodes.push(ApprovalNode.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ApprovalStep {
    return {
      type: isSet(object.type) ? approvalStep_TypeFromJSON(object.type) : 0,
      nodes: Array.isArray(object?.nodes) ? object.nodes.map((e: any) => ApprovalNode.fromJSON(e)) : [],
    };
  },

  toJSON(message: ApprovalStep): unknown {
    const obj: any = {};
    message.type !== undefined && (obj.type = approvalStep_TypeToJSON(message.type));
    if (message.nodes) {
      obj.nodes = message.nodes.map((e) => e ? ApprovalNode.toJSON(e) : undefined);
    } else {
      obj.nodes = [];
    }
    return obj;
  },

  create(base?: DeepPartial<ApprovalStep>): ApprovalStep {
    return ApprovalStep.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ApprovalStep>): ApprovalStep {
    const message = createBaseApprovalStep();
    message.type = object.type ?? 0;
    message.nodes = object.nodes?.map((e) => ApprovalNode.fromPartial(e)) || [];
    return message;
  },
};

function createBaseApprovalNode(): ApprovalNode {
  return { type: 0, groupValue: undefined, role: undefined, externalNodeId: undefined };
}

export const ApprovalNode = {
  encode(message: ApprovalNode, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.groupValue !== undefined) {
      writer.uint32(16).int32(message.groupValue);
    }
    if (message.role !== undefined) {
      writer.uint32(26).string(message.role);
    }
    if (message.externalNodeId !== undefined) {
      writer.uint32(34).string(message.externalNodeId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ApprovalNode {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseApprovalNode();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.type = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.groupValue = reader.int32() as any;
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.role = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.externalNodeId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ApprovalNode {
    return {
      type: isSet(object.type) ? approvalNode_TypeFromJSON(object.type) : 0,
      groupValue: isSet(object.groupValue) ? approvalNode_GroupValueFromJSON(object.groupValue) : undefined,
      role: isSet(object.role) ? String(object.role) : undefined,
      externalNodeId: isSet(object.externalNodeId) ? String(object.externalNodeId) : undefined,
    };
  },

  toJSON(message: ApprovalNode): unknown {
    const obj: any = {};
    message.type !== undefined && (obj.type = approvalNode_TypeToJSON(message.type));
    message.groupValue !== undefined &&
      (obj.groupValue = message.groupValue !== undefined
        ? approvalNode_GroupValueToJSON(message.groupValue)
        : undefined);
    message.role !== undefined && (obj.role = message.role);
    message.externalNodeId !== undefined && (obj.externalNodeId = message.externalNodeId);
    return obj;
  },

  create(base?: DeepPartial<ApprovalNode>): ApprovalNode {
    return ApprovalNode.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ApprovalNode>): ApprovalNode {
    const message = createBaseApprovalNode();
    message.type = object.type ?? 0;
    message.groupValue = object.groupValue ?? undefined;
    message.role = object.role ?? undefined;
    message.externalNodeId = object.externalNodeId ?? undefined;
    return message;
  },
};

function createBaseCreateIssueCommentRequest(): CreateIssueCommentRequest {
  return { parent: "", reviewComment: undefined };
}

export const CreateIssueCommentRequest = {
  encode(message: CreateIssueCommentRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.parent !== "") {
      writer.uint32(10).string(message.parent);
    }
    if (message.reviewComment !== undefined) {
      ReviewComment.encode(message.reviewComment, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CreateIssueCommentRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCreateIssueCommentRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.parent = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.reviewComment = ReviewComment.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): CreateIssueCommentRequest {
    return {
      parent: isSet(object.parent) ? String(object.parent) : "",
      reviewComment: isSet(object.reviewComment) ? ReviewComment.fromJSON(object.reviewComment) : undefined,
    };
  },

  toJSON(message: CreateIssueCommentRequest): unknown {
    const obj: any = {};
    message.parent !== undefined && (obj.parent = message.parent);
    message.reviewComment !== undefined &&
      (obj.reviewComment = message.reviewComment ? ReviewComment.toJSON(message.reviewComment) : undefined);
    return obj;
  },

  create(base?: DeepPartial<CreateIssueCommentRequest>): CreateIssueCommentRequest {
    return CreateIssueCommentRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<CreateIssueCommentRequest>): CreateIssueCommentRequest {
    const message = createBaseCreateIssueCommentRequest();
    message.parent = object.parent ?? "";
    message.reviewComment = (object.reviewComment !== undefined && object.reviewComment !== null)
      ? ReviewComment.fromPartial(object.reviewComment)
      : undefined;
    return message;
  },
};

function createBaseUpdateIssueCommentRequest(): UpdateIssueCommentRequest {
  return { parent: "", reviewComment: undefined, updateMask: undefined };
}

export const UpdateIssueCommentRequest = {
  encode(message: UpdateIssueCommentRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.parent !== "") {
      writer.uint32(10).string(message.parent);
    }
    if (message.reviewComment !== undefined) {
      ReviewComment.encode(message.reviewComment, writer.uint32(18).fork()).ldelim();
    }
    if (message.updateMask !== undefined) {
      FieldMask.encode(FieldMask.wrap(message.updateMask), writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): UpdateIssueCommentRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseUpdateIssueCommentRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.parent = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.reviewComment = ReviewComment.decode(reader, reader.uint32());
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.updateMask = FieldMask.unwrap(FieldMask.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): UpdateIssueCommentRequest {
    return {
      parent: isSet(object.parent) ? String(object.parent) : "",
      reviewComment: isSet(object.reviewComment) ? ReviewComment.fromJSON(object.reviewComment) : undefined,
      updateMask: isSet(object.updateMask) ? FieldMask.unwrap(FieldMask.fromJSON(object.updateMask)) : undefined,
    };
  },

  toJSON(message: UpdateIssueCommentRequest): unknown {
    const obj: any = {};
    message.parent !== undefined && (obj.parent = message.parent);
    message.reviewComment !== undefined &&
      (obj.reviewComment = message.reviewComment ? ReviewComment.toJSON(message.reviewComment) : undefined);
    message.updateMask !== undefined && (obj.updateMask = FieldMask.toJSON(FieldMask.wrap(message.updateMask)));
    return obj;
  },

  create(base?: DeepPartial<UpdateIssueCommentRequest>): UpdateIssueCommentRequest {
    return UpdateIssueCommentRequest.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<UpdateIssueCommentRequest>): UpdateIssueCommentRequest {
    const message = createBaseUpdateIssueCommentRequest();
    message.parent = object.parent ?? "";
    message.reviewComment = (object.reviewComment !== undefined && object.reviewComment !== null)
      ? ReviewComment.fromPartial(object.reviewComment)
      : undefined;
    message.updateMask = object.updateMask ?? undefined;
    return message;
  },
};

function createBaseReviewComment(): ReviewComment {
  return { uid: "", comment: "", payload: "", createTime: undefined, updateTime: undefined };
}

export const ReviewComment = {
  encode(message: ReviewComment, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.uid !== "") {
      writer.uint32(10).string(message.uid);
    }
    if (message.comment !== "") {
      writer.uint32(18).string(message.comment);
    }
    if (message.payload !== "") {
      writer.uint32(26).string(message.payload);
    }
    if (message.createTime !== undefined) {
      Timestamp.encode(toTimestamp(message.createTime), writer.uint32(34).fork()).ldelim();
    }
    if (message.updateTime !== undefined) {
      Timestamp.encode(toTimestamp(message.updateTime), writer.uint32(42).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ReviewComment {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseReviewComment();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.uid = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.comment = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.payload = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.createTime = fromTimestamp(Timestamp.decode(reader, reader.uint32()));
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.updateTime = fromTimestamp(Timestamp.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ReviewComment {
    return {
      uid: isSet(object.uid) ? String(object.uid) : "",
      comment: isSet(object.comment) ? String(object.comment) : "",
      payload: isSet(object.payload) ? String(object.payload) : "",
      createTime: isSet(object.createTime) ? fromJsonTimestamp(object.createTime) : undefined,
      updateTime: isSet(object.updateTime) ? fromJsonTimestamp(object.updateTime) : undefined,
    };
  },

  toJSON(message: ReviewComment): unknown {
    const obj: any = {};
    message.uid !== undefined && (obj.uid = message.uid);
    message.comment !== undefined && (obj.comment = message.comment);
    message.payload !== undefined && (obj.payload = message.payload);
    message.createTime !== undefined && (obj.createTime = message.createTime.toISOString());
    message.updateTime !== undefined && (obj.updateTime = message.updateTime.toISOString());
    return obj;
  },

  create(base?: DeepPartial<ReviewComment>): ReviewComment {
    return ReviewComment.fromPartial(base ?? {});
  },

  fromPartial(object: DeepPartial<ReviewComment>): ReviewComment {
    const message = createBaseReviewComment();
    message.uid = object.uid ?? "";
    message.comment = object.comment ?? "";
    message.payload = object.payload ?? "";
    message.createTime = object.createTime ?? undefined;
    message.updateTime = object.updateTime ?? undefined;
    return message;
  },
};

export type IssueServiceDefinition = typeof IssueServiceDefinition;
export const IssueServiceDefinition = {
  name: "IssueService",
  fullName: "bytebase.v1.IssueService",
  methods: {
    getIssue: {
      name: "GetIssue",
      requestType: GetIssueRequest,
      requestStream: false,
      responseType: Review,
      responseStream: false,
      options: {
        _unknownFields: {
          8410: [new Uint8Array([4, 110, 97, 109, 101])],
          578365826: [
            new Uint8Array([
              33,
              18,
              31,
              47,
              118,
              49,
              47,
              123,
              110,
              97,
              109,
              101,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              47,
              42,
              125,
            ]),
          ],
        },
      },
    },
    createIssue: {
      name: "CreateIssue",
      requestType: CreateIssueRequest,
      requestStream: false,
      responseType: Review,
      responseStream: false,
      options: {
        _unknownFields: {
          8410: [new Uint8Array([13, 112, 97, 114, 101, 110, 116, 44, 114, 101, 118, 105, 101, 119])],
          578365826: [
            new Uint8Array([
              41,
              58,
              6,
              114,
              101,
              118,
              105,
              101,
              119,
              34,
              31,
              47,
              118,
              49,
              47,
              123,
              112,
              97,
              114,
              101,
              110,
              116,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              125,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
            ]),
          ],
        },
      },
    },
    listIssues: {
      name: "ListIssues",
      requestType: ListIssuesRequest,
      requestStream: false,
      responseType: ListIssuesResponse,
      responseStream: false,
      options: {
        _unknownFields: {
          8410: [new Uint8Array([6, 112, 97, 114, 101, 110, 116])],
          578365826: [
            new Uint8Array([
              33,
              18,
              31,
              47,
              118,
              49,
              47,
              123,
              112,
              97,
              114,
              101,
              110,
              116,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              125,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
            ]),
          ],
        },
      },
    },
    updateIssue: {
      name: "UpdateIssue",
      requestType: UpdateIssueRequest,
      requestStream: false,
      responseType: Review,
      responseStream: false,
      options: {
        _unknownFields: {
          8410: [
            new Uint8Array([18, 114, 101, 118, 105, 101, 119, 44, 117, 112, 100, 97, 116, 101, 95, 109, 97, 115, 107]),
          ],
          578365826: [
            new Uint8Array([
              48,
              58,
              6,
              114,
              101,
              118,
              105,
              101,
              119,
              50,
              38,
              47,
              118,
              49,
              47,
              123,
              114,
              101,
              118,
              105,
              101,
              119,
              46,
              110,
              97,
              109,
              101,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              47,
              42,
              125,
            ]),
          ],
        },
      },
    },
    createIssueComment: {
      name: "CreateIssueComment",
      requestType: CreateIssueCommentRequest,
      requestStream: false,
      responseType: ReviewComment,
      responseStream: false,
      options: {
        _unknownFields: {
          8410: [
            new Uint8Array([
              21,
              112,
              97,
              114,
              101,
              110,
              116,
              44,
              114,
              101,
              118,
              105,
              101,
              119,
              95,
              99,
              111,
              109,
              109,
              101,
              110,
              116,
            ]),
          ],
          578365826: [
            new Uint8Array([
              59,
              58,
              14,
              114,
              101,
              118,
              105,
              101,
              119,
              95,
              99,
              111,
              109,
              109,
              101,
              110,
              116,
              34,
              41,
              47,
              118,
              49,
              47,
              123,
              112,
              97,
              114,
              101,
              110,
              116,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              47,
              42,
              125,
              58,
              99,
              111,
              109,
              109,
              101,
              110,
              116,
            ]),
          ],
        },
      },
    },
    updateIssueComment: {
      name: "UpdateIssueComment",
      requestType: UpdateIssueCommentRequest,
      requestStream: false,
      responseType: ReviewComment,
      responseStream: false,
      options: {
        _unknownFields: {
          8410: [
            new Uint8Array([
              33,
              112,
              97,
              114,
              101,
              110,
              116,
              44,
              114,
              101,
              118,
              105,
              101,
              119,
              95,
              99,
              111,
              109,
              109,
              101,
              110,
              116,
              44,
              117,
              112,
              100,
              97,
              116,
              101,
              95,
              109,
              97,
              115,
              107,
            ]),
          ],
          578365826: [
            new Uint8Array([
              59,
              58,
              14,
              114,
              101,
              118,
              105,
              101,
              119,
              95,
              99,
              111,
              109,
              109,
              101,
              110,
              116,
              50,
              41,
              47,
              118,
              49,
              47,
              123,
              112,
              97,
              114,
              101,
              110,
              116,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              47,
              42,
              125,
              58,
              99,
              111,
              109,
              109,
              101,
              110,
              116,
            ]),
          ],
        },
      },
    },
    batchUpdateIssues: {
      name: "BatchUpdateIssues",
      requestType: BatchUpdateIssuesRequest,
      requestStream: false,
      responseType: BatchUpdateIssuesResponse,
      responseStream: false,
      options: {
        _unknownFields: {
          578365826: [
            new Uint8Array([
              48,
              58,
              1,
              42,
              34,
              43,
              47,
              118,
              49,
              47,
              123,
              112,
              97,
              114,
              101,
              110,
              116,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              125,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              58,
              98,
              97,
              116,
              99,
              104,
              85,
              112,
              100,
              97,
              116,
              101,
            ]),
          ],
        },
      },
    },
    approveReview: {
      name: "ApproveReview",
      requestType: ApproveReviewRequest,
      requestStream: false,
      responseType: Review,
      responseStream: false,
      options: {
        _unknownFields: {
          578365826: [
            new Uint8Array([
              44,
              58,
              1,
              42,
              34,
              39,
              47,
              118,
              49,
              47,
              123,
              110,
              97,
              109,
              101,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              47,
              42,
              125,
              58,
              97,
              112,
              112,
              114,
              111,
              118,
              101,
            ]),
          ],
        },
      },
    },
    rejectReview: {
      name: "RejectReview",
      requestType: RejectReviewRequest,
      requestStream: false,
      responseType: Review,
      responseStream: false,
      options: {
        _unknownFields: {
          578365826: [
            new Uint8Array([
              43,
              58,
              1,
              42,
              34,
              38,
              47,
              118,
              49,
              47,
              123,
              110,
              97,
              109,
              101,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              47,
              42,
              125,
              58,
              114,
              101,
              106,
              101,
              99,
              116,
            ]),
          ],
        },
      },
    },
    requestReview: {
      name: "RequestReview",
      requestType: RequestReviewRequest,
      requestStream: false,
      responseType: Review,
      responseStream: false,
      options: {
        _unknownFields: {
          578365826: [
            new Uint8Array([
              44,
              58,
              1,
              42,
              34,
              39,
              47,
              118,
              49,
              47,
              123,
              110,
              97,
              109,
              101,
              61,
              112,
              114,
              111,
              106,
              101,
              99,
              116,
              115,
              47,
              42,
              47,
              114,
              101,
              118,
              105,
              101,
              119,
              115,
              47,
              42,
              125,
              58,
              114,
              101,
              113,
              117,
              101,
              115,
              116,
            ]),
          ],
        },
      },
    },
  },
} as const;

export interface IssueServiceImplementation<CallContextExt = {}> {
  getIssue(request: GetIssueRequest, context: CallContext & CallContextExt): Promise<DeepPartial<Review>>;
  createIssue(request: CreateIssueRequest, context: CallContext & CallContextExt): Promise<DeepPartial<Review>>;
  listIssues(
    request: ListIssuesRequest,
    context: CallContext & CallContextExt,
  ): Promise<DeepPartial<ListIssuesResponse>>;
  updateIssue(request: UpdateIssueRequest, context: CallContext & CallContextExt): Promise<DeepPartial<Review>>;
  createIssueComment(
    request: CreateIssueCommentRequest,
    context: CallContext & CallContextExt,
  ): Promise<DeepPartial<ReviewComment>>;
  updateIssueComment(
    request: UpdateIssueCommentRequest,
    context: CallContext & CallContextExt,
  ): Promise<DeepPartial<ReviewComment>>;
  batchUpdateIssues(
    request: BatchUpdateIssuesRequest,
    context: CallContext & CallContextExt,
  ): Promise<DeepPartial<BatchUpdateIssuesResponse>>;
  approveReview(request: ApproveReviewRequest, context: CallContext & CallContextExt): Promise<DeepPartial<Review>>;
  rejectReview(request: RejectReviewRequest, context: CallContext & CallContextExt): Promise<DeepPartial<Review>>;
  requestReview(request: RequestReviewRequest, context: CallContext & CallContextExt): Promise<DeepPartial<Review>>;
}

export interface IssueServiceClient<CallOptionsExt = {}> {
  getIssue(request: DeepPartial<GetIssueRequest>, options?: CallOptions & CallOptionsExt): Promise<Review>;
  createIssue(request: DeepPartial<CreateIssueRequest>, options?: CallOptions & CallOptionsExt): Promise<Review>;
  listIssues(
    request: DeepPartial<ListIssuesRequest>,
    options?: CallOptions & CallOptionsExt,
  ): Promise<ListIssuesResponse>;
  updateIssue(request: DeepPartial<UpdateIssueRequest>, options?: CallOptions & CallOptionsExt): Promise<Review>;
  createIssueComment(
    request: DeepPartial<CreateIssueCommentRequest>,
    options?: CallOptions & CallOptionsExt,
  ): Promise<ReviewComment>;
  updateIssueComment(
    request: DeepPartial<UpdateIssueCommentRequest>,
    options?: CallOptions & CallOptionsExt,
  ): Promise<ReviewComment>;
  batchUpdateIssues(
    request: DeepPartial<BatchUpdateIssuesRequest>,
    options?: CallOptions & CallOptionsExt,
  ): Promise<BatchUpdateIssuesResponse>;
  approveReview(request: DeepPartial<ApproveReviewRequest>, options?: CallOptions & CallOptionsExt): Promise<Review>;
  rejectReview(request: DeepPartial<RejectReviewRequest>, options?: CallOptions & CallOptionsExt): Promise<Review>;
  requestReview(request: DeepPartial<RequestReviewRequest>, options?: CallOptions & CallOptionsExt): Promise<Review>;
}

type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;

export type DeepPartial<T> = T extends Builtin ? T
  : T extends Array<infer U> ? Array<DeepPartial<U>> : T extends ReadonlyArray<infer U> ? ReadonlyArray<DeepPartial<U>>
  : T extends {} ? { [K in keyof T]?: DeepPartial<T[K]> }
  : Partial<T>;

function toTimestamp(date: Date): Timestamp {
  const seconds = date.getTime() / 1_000;
  const nanos = (date.getTime() % 1_000) * 1_000_000;
  return { seconds, nanos };
}

function fromTimestamp(t: Timestamp): Date {
  let millis = (t.seconds || 0) * 1_000;
  millis += (t.nanos || 0) / 1_000_000;
  return new Date(millis);
}

function fromJsonTimestamp(o: any): Date {
  if (o instanceof Date) {
    return o;
  } else if (typeof o === "string") {
    return new Date(o);
  } else {
    return fromTimestamp(Timestamp.fromJSON(o));
  }
}

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}

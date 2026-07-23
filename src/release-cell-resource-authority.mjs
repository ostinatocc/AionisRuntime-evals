/*
 * Public release-resource surface. Minting is intentionally module-private to
 * release-cell-resource-provisioner.mjs; callers can only claim or dispose a
 * handle that the live provisioner produced.
 */
export {
  claimReleaseCellResourceAuthorityV1,
  disposeReleaseCellResourceAuthorityV1,
} from "./release-cell-resource-provisioner.mjs";

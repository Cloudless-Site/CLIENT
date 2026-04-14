# Cloudless ownership and refcount notes

## Service lifecycle

A service stays local until it is fully prepared. After `svc_tab_insert()` the instance is globally visible and rollback must use unlink plus `svc_release()`, never direct `free()`.

`dux_add_service()` follows this rule:

- allocate `cl_svc` and `cl_svc_cold`
- prepare ports and optional UDP NAT resources
- retain session if present
- validate hostname and flags
- publish with `svc_tab_insert()`
- if publish-side work fails, use `dux_unlink_service_all()` and `svc_release()`

## Session and service links

`svc->sess` is retained with `sess_retain()` before linking. When a published service is torn down the release path is `svc_release()` -> `svc_destroy_impl()` -> `sess_release()`.

`svc_free_new()` is reserved for never-published instances only.

## Flow and worker ownership

UDP flows attached to worker session structures must be detached before free on every cleanup path. Global flow-table unlink is not enough on its own.

TCP worker connection maps must clear an fd slot only if the slot still points to the connection being closed.

## Runtime install split

`install-prep` builds into `Cloudless-work`. `install-root` copies prepared artifacts into the runtime tree. Root must not rebuild inside the workspace.
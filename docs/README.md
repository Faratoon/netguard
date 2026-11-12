# Router admin screenshots

Drop the router admin screenshots here (for example `router1.jpg`) and import them
into the NetGuard gallery so the "Images" tab shows the router admin data you
captured:

```bash
./scripts/import_router_screenshot.sh docs/router1.jpg http://localhost:8080
```

The image is stored under `data/media/` and can be attached to a device
(`PATCH /api/devices/{id}` with `photo_path`) or used as evidence next to a
blocked-page event.

NetGuard itself can also read the live admin data directly from the router
(`GET /api/admin/info`) — the screenshots are only for archiving what the
router web UI showed at a given moment.

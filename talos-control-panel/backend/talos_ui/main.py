from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config
from .routers import (
    access, attack, auth, auth_config, configuration, console, endpoints,
    error_intel, findings, flows, input_validation, intruder, mutations, modules,
    passive, projects, proxy, replay, roles, scheduler, send,
)

app = FastAPI(title="Talos Control Panel API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in (
    projects.router, proxy.router, roles.router, modules.router,
    access.router, auth.router, auth_config.router, endpoints.router,
    flows.router, replay.router, send.router, scheduler.router, mutations.router,
    attack.router, input_validation.router, passive.router,
    error_intel.router, findings.router, console.router, configuration.router,
    intruder.router,
):
    app.include_router(router)


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "talos_home": str(config.TALOS_HOME),
        "projects_root": str(config.PROJECTS_ROOT),
        "talos_bin": config.TALOS_BIN,
        "registry_exists": config.REGISTRY_PATH.exists(),
    }

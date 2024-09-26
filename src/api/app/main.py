from fastapi import FastAPI
from .entry import routers as entry
from .analyse import routers as analyse
from .alerts import routers as alerts
from .stats import routers as stats

app = FastAPI()

app.include_router(entry.router)
app.include_router(analyse.router)
app.include_router(stats.router)
app.include_router(alerts.router)

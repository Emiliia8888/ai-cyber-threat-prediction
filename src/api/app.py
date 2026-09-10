from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.api.routes import router
from src.application.composition import create_threat_analysis
from src.config.settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    app.state.analysis = create_threat_analysis(settings)

    yield


app = FastAPI(
    title="AI Cyber Threat Prediction API",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)

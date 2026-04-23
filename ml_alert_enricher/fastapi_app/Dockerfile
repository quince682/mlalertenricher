# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base
WORKDIR /app
FROM base AS builder
COPY --link requirements.txt ./

#RUN --mount=type=cache,target=/root/.cache/pip \
#    python -m venv .venv && \
#   .venv/bin/pip install -r requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv .venv && \
    .venv/bin/pip install --default-timeout=1000 --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY --link . .
FROM base AS final
# Create a non-root user and group
RUN addgroup --system appuser && adduser --system --ingroup appuser appuser
# Copy app code and venv from builder
COPY --from=builder /app /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
# Set permissions for the non-root user
RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

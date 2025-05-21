# Contextual

A project exploring lazy evaluation of side-effects in Python

## Notes

Project is managed by [uv](https://docs.astral.sh/uv/). To get it to run you need to have an OIDC compliant service and define a few environment varibles in an `.env` file.

You can run this with

`uv run --env-file .env python main.py`


### ENV VARS

- **DOMAIN**: The domain of the oidc server
- **CLIENT_ID**: The application registered on the oidc server (should be able to support the device code flow and refresh tokens)
- **AUDIENCE**: The API registered on the oidc server

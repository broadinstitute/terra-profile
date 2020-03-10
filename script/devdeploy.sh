set +x

gcloud app deploy --version="$USER-dev" --no-promote \
  --project=broad-shibboleth-prod --account="$USER"@broadinstitute.org

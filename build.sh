#!/usr/bin/env bash
# Exit on error
set -o errexit

# Modify this line as needed for your project
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Apply database migrations
python manage.py migrate

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl pandoc openssl \
    fontconfig libfreetype6 libjpeg62-turbo libpng16-16t64 libx11-6 libxcb1 \
    libxext6 libxrender1 xfonts-75dpi xfonts-base \
    && rm -rf /var/lib/apt/lists/*

# Install wkhtmltopdf from official releases (not available in Debian Trixie repos)
RUN curl -L -o /tmp/wkhtmltopdf.deb https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.bookworm_amd64.deb \
    && dpkg -i /tmp/wkhtmltopdf.deb || apt-get install -f -y \
    && rm /tmp/wkhtmltopdf.deb

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py index.html index_simple.html ./

EXPOSE 8000

# Gunicorn for production
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "server:app"]

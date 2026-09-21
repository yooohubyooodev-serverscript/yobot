FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .
COPY core/ core/
COPY engines/ engines/

RUN mkdir -p work

# No advanced native engines are bundled.
# Only static Python preprocessors are available.

CMD ["python", "bot.py"]

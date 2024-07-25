# Используем официальный Python образ
FROM python:3.9-slim

# Устанавливаем необходимые зависимости
RUN apt-get update && apt-get install -y \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Создаем рабочую директорию
WORKDIR /app

# Копируем содержимое текущей директории в контейнер
COPY . /app

# Устанавливаем зависимости Python из requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Указываем команду для запуска скрипта по умолчанию
ENTRYPOINT ["python"]

# Указываем скрипт по умолчанию
CMD ["start.py"]
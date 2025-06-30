FROM python:3.12-bookworm
LABEL maintainer="SYNETIS <cert@synetis.com>"
WORKDIR "/vesta"
COPY . .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
VOLUME ["/output"]
EXPOSE 5000
ENTRYPOINT [ "python", "main.py" ]
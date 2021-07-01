FROM rust

RUN apt-get update && apt-get install clang -y

WORKDIR /usr/src/trin
COPY . .

RUN cargo install --path .

ENV TRIN_INFURA_PROJECT_ID="xxx"

CMD ["trin"]

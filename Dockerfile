FROM rust

RUN apt-get update 

#
# based on Rocksdb install.md:
#

# Upgrade your gcc to version at least 4.7 to get C++11 support.
RUN apt-get install -y build-essential checkinstall

# Install gflags
RUN apt-get install -y libgflags-dev

# Install snappy
RUN apt-get install -y libsnappy-dev

# Install zlib
RUN apt-get install -y zlib1g-dev

# Install bzip2
RUN apt-get install -y libbz2-dev

# Clone rocksdb
RUN cd /tmp && git clone https://github.com/facebook/rocksdb.git && cd rocksdb && make clean && make


WORKDIR /usr/src/trin
COPY . .

RUN cargo install --path .

CMD ["trin"]

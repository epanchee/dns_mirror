FROM rustembedded/cross:mipsel-unknown-linux-gnu-0.2.1

RUN apt update && apt install -y libpcap-dev flex bison
RUN curl https://www.tcpdump.org/release/libpcap-1.10.0.tar.gz -o libpcap.tar.gz && tar xzf libpcap.tar.gz
RUN cd libpcap-1.10.0/ && CC=mipsel-linux-gnu-gcc ./configure --host=mipsel-linux-gnu --with-pcap=linux
RUN cd libpcap-1.10.0/ && make -j4 && make install
RUN rm -rf libpcap-1.10.0.tar.gz libpcap-1.10.0 && apt clean

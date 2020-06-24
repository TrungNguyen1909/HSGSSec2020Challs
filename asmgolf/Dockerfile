FROM natsukagami/kjudge:v0.6.0

RUN apt-get update && apt-get install -y cmake git xxd
RUN git clone https://github.com/keystone-engine/keystone
RUN cd keystone && mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="X86" -G "Unix Makefiles" .. && make -j8 && make install
RUN git clone https://github.com/unicorn-engine/unicorn
RUN cd unicorn && ./make.sh && ./make.sh install
RUN cp /usr/local/lib/libkeystone.so.0 /usr/lib
RUN ln -s /usr/lib/libkeystone.so.0 /usr/lib/libkeystone.so
RUN rm -rf keystone unicorn
RUN ldconfig

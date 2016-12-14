require "../src/libtls"

HOST = "www.google.com"
PORT = "443"

LibTls.tls_init
ctx = LibTls.tls_client
config = LibTls.tls_config_new
LibTls.tls_config_set_protocols(config, LibTls::TLS_PROTOCOL_TLSv1_2)
LibTls.tls_configure(ctx, config)
LibTls.tls_connect(ctx, HOST, PORT)
LibTls.tls_handshake(ctx)

message = "GET / HTTP/1.1\r\nHost: #{HOST}\r\n\r\n"
LibTls.tls_write(ctx, message, message.size)

buf = Bytes.new(0xffff)
len = LibTls.tls_read(ctx, buf, 0xffff)
pointer = buf.pointer(buf.size)
puts String.new(pointer.to_slice(len))

LibTls.tls_close(ctx)
LibTls.tls_config_free(config)
LibTls.tls_free(ctx)

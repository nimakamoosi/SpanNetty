﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Transport.Channels.Sockets
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading.Tasks;
    using DotNetty.Buffers;
    using DotNetty.Common.Concurrency;

    public sealed class TcpSocketChannel : TcpSocketChannel<TcpSocketChannel>
    {
        /// <summary>Create a new instance</summary>
        public TcpSocketChannel() : base() { }

        /// <summary>Create a new instance</summary>
        public TcpSocketChannel(AddressFamily addressFamily) : base(addressFamily) { }

        /// <summary>Create a new instance using the given <see cref="ISocketChannel" />.</summary>
        public TcpSocketChannel(Socket socket) : base(socket) { }

        /// <summary>Create a new instance</summary>
        /// <param name="parent">
        ///     the <see cref="IChannel" /> which created this instance or <c>null</c> if it was created by the
        ///     user
        /// </param>
        /// <param name="socket">the <see cref="ISocketChannel" /> which will be used</param>
        public TcpSocketChannel(IChannel parent, Socket socket) : base(parent, socket) { }

        internal TcpSocketChannel(IChannel parent, Socket socket, bool connected) : base(parent, socket, connected) { }
    }

    /// <summary>
    ///     <see cref="ISocketChannel" /> which uses Socket-based implementation.
    /// </summary>
    public partial class TcpSocketChannel<TChannel> : AbstractSocketByteChannel<TChannel, TcpSocketChannel<TChannel>.TcpSocketChannelUnsafe>, ISocketChannel
        where TChannel : TcpSocketChannel<TChannel>
    {
        private static readonly Action<object, object> ShutdownOutputAction = OnShutdownOutput;

        private static readonly ChannelMetadata METADATA = new ChannelMetadata(false, 16);

        private readonly ISocketChannelConfiguration _config;

        /// <summary>Create a new instance</summary>
        public TcpSocketChannel()
            : this(null, SocketEx.CreateSocket(), false) //new Socket(SocketType.Stream, ProtocolType.Tcp))
        {
        }

        /// <summary>Create a new instance</summary>
        public TcpSocketChannel(AddressFamily addressFamily)
            : this(null, SocketEx.CreateSocket(addressFamily), false) //new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp))
        {
        }

        /// <summary>Create a new instance using the given <see cref="ISocketChannel" />.</summary>
        public TcpSocketChannel(Socket socket)
            : this(null, socket, false)
        {
        }

        /// <summary>Create a new instance</summary>
        /// <param name="parent">
        ///     the <see cref="IChannel" /> which created this instance or <c>null</c> if it was created by the
        ///     user
        /// </param>
        /// <param name="socket">the <see cref="ISocketChannel" /> which will be used</param>
        public TcpSocketChannel(IChannel parent, Socket socket)
            : this(parent, socket, false)
        {
        }

        protected TcpSocketChannel(IChannel parent, Socket socket, bool connected)
            : base(parent, socket)
        {
            _config = new TcpSocketChannelConfig((TChannel)this, socket);
            if (connected)
            {
                OnConnected();
            }
        }

        public override ChannelMetadata Metadata => METADATA;

        public override IChannelConfiguration Configuration => _config;

        protected override EndPoint LocalAddressInternal => Socket.LocalEndPoint;

        protected override EndPoint RemoteAddressInternal => Socket.RemoteEndPoint;

        public bool IsOutputShutdown
        {
            get { throw new NotImplementedException(); } // todo: impl with stateflags
        }

        public Task ShutdownOutputAsync()
        {
            var tcs = NewPromise();
            // todo: use closeExecutor if available
            //Executor closeExecutor = ((TcpSocketChannelUnsafe) unsafe()).closeExecutor();
            //if (closeExecutor is object) {
            //    closeExecutor.execute(new OneTimeTask() {

            //        public void run() {
            //            shutdownOutput0(promise);
            //        }
            //    });
            //} else {
            IEventLoop loop = EventLoop;
            if (loop.InEventLoop)
            {
                ShutdownOutput0(tcs);
            }
            else
            {
                loop.Execute(ShutdownOutputAction, this, tcs);
            }
            //}
            return tcs.Task;
        }

        void ShutdownOutput0(IPromise promise)
        {
            try
            {
                Socket.Shutdown(SocketShutdown.Send);
                promise.Complete();
            }
            catch (Exception ex)
            {
                promise.SetException(ex);
            }
        }

        private static void OnShutdownOutput(object channel, object promise)
        {
            ((TcpSocketChannel<TChannel>)channel).ShutdownOutput0((IPromise)promise);
        }

        protected override void DoBind(EndPoint localAddress) => Socket.Bind(localAddress);

        protected override bool DoConnect(EndPoint remoteAddress, EndPoint localAddress)
        {
            if (localAddress is object)
            {
                Socket.Bind(localAddress);
            }

            bool success = false;
            try
            {
                var eventPayload = new SocketChannelAsyncOperation<TChannel, TcpSocketChannelUnsafe>((TChannel)this, false)
                {
                    RemoteEndPoint = remoteAddress
                };
                bool connected = !Socket.ConnectAsync(eventPayload);
                if (connected)
                {
                    DoFinishConnect(eventPayload);
                }
                success = true;
                return connected;
            }
            finally
            {
                if (!success)
                {
                    DoClose();
                }
            }
        }

        protected override void DoFinishConnect(SocketChannelAsyncOperation<TChannel, TcpSocketChannelUnsafe> operation)
        {
            try
            {
                operation.Validate();
            }
            finally
            {
                operation.Dispose();
            }
            OnConnected();
        }

        void OnConnected()
        {
            SetState(StateFlags.Active);

            // preserve local and remote addresses for later availability even if Socket fails
            _ = CacheLocalAddress();
            _ = CacheRemoteAddress();
        }

        protected override void DoDisconnect() => DoClose();

        protected override void DoClose()
        {
            try
            {
                if (TryResetState(StateFlags.Open))
                {
                    if (TryResetState(StateFlags.Active))
                    {
                        Socket.Shutdown(SocketShutdown.Both);
                    }
                    Socket.SafeClose(); //this.Socket.Dispose();
                }
            }
            finally
            {
                base.DoClose();
            }
        }

        protected override int DoReadBytes(IByteBuffer byteBuf)
        {
            if (!byteBuf.HasArray)
            {
                ThrowHelper.ThrowNotImplementedException_OnlyIByteBufferImpl();
            }

            if (!Socket.Connected)
            {
                return -1; // prevents ObjectDisposedException from being thrown in case connection has been lost in the meantime
            }

#if NETCOREAPP || NETSTANDARD_2_0_GREATER
            int received = Socket.Receive(byteBuf.FreeSpan, SocketFlags.None, out SocketError errorCode);
#else
            int received = Socket.Receive(byteBuf.Array, byteBuf.ArrayOffset + byteBuf.WriterIndex, byteBuf.WritableBytes, SocketFlags.None, out SocketError errorCode);
#endif

            switch (errorCode)
            {
                case SocketError.Success:
                    if (0u >= (uint)received)
                    {
                        return -1; // indicate that socket was closed
                    }
                    break;
                case SocketError.WouldBlock:
                    if (0u >= (uint)received)
                    {
                        return 0;
                    }
                    break;
                default:
                    ThrowHelper.ThrowSocketException(errorCode); break;
            }

            byteBuf.SetWriterIndex(byteBuf.WriterIndex + received);

            return received;
        }

        protected override int DoWriteBytes(IByteBuffer buf)
        {
            if (!buf.HasArray)
            {
                ThrowHelper.ThrowNotImplementedException_OnlyIByteBufferImpl();
            }

            int sent = Socket.Send(buf.Array, buf.ArrayOffset + buf.ReaderIndex, buf.ReadableBytes, SocketFlags.None, out SocketError errorCode);

            if (errorCode != SocketError.Success && errorCode != SocketError.WouldBlock)
            {
                ThrowHelper.ThrowSocketException(errorCode);
            }

            if (sent > 0)
            {
                _ = buf.SetReaderIndex(buf.ReaderIndex + sent);
            }

            return sent;
        }

        //protected long doWriteFileRegion(FileRegion region)
        //{
        //    long position = region.transfered();
        //    return region.transferTo(javaChannel(), position);
        //}

        protected override void DoWrite(ChannelOutboundBuffer input)
        {
            List<ArraySegment<byte>> sharedBufferList = null;
            var socketConfig = (TcpSocketChannelConfig)_config;
            Socket socket = Socket;
            var writeSpinCount = socketConfig.WriteSpinCount;
            try
            {
                while (true)
                {
                    int size = input.Size;
                    if (0u >= (uint)size)
                    {
                        // All written
                        break;
                    }
                    long writtenBytes = 0;
                    bool done = false;

                    // Ensure the pending writes are made of ByteBufs only.
                    int maxBytesPerGatheringWrite = socketConfig.GetMaxBytesPerGatheringWrite();
                    sharedBufferList = input.GetSharedBufferList(1024, maxBytesPerGatheringWrite);
                    int nioBufferCnt = sharedBufferList.Count;
                    long expectedWrittenBytes = input.NioBufferSize;

                    List<ArraySegment<byte>> bufferList = sharedBufferList;
                    // Always us nioBuffers() to workaround data-corruption.
                    // See https://github.com/netty/netty/issues/2761
                    switch (nioBufferCnt)
                    {
                        case 0:
                            // We have something else beside ByteBuffers to write so fallback to normal writes.
                            base.DoWrite(input);
                            return;
                        default:
                            for (int i = writeSpinCount - 1; i >= 0; i--)
                            {
                                long localWrittenBytes = socket.Send(bufferList, SocketFlags.None, out SocketError errorCode);
                                if (errorCode != SocketError.Success && errorCode != SocketError.WouldBlock)
                                {
                                    ThrowHelper.ThrowSocketException(errorCode);
                                }

                                if (0ul >= (ulong)localWrittenBytes)
                                {
                                    break;
                                }

                                expectedWrittenBytes -= localWrittenBytes;
                                writtenBytes += localWrittenBytes;
                                if (0ul >= (ulong)expectedWrittenBytes)
                                {
                                    done = true;
                                    break;
                                }
                                else
                                {
                                    bufferList = AdjustBufferList(localWrittenBytes, bufferList);
                                }
                            }
                            break;
                    }

                    if (writtenBytes > 0)
                    {
                        // Release the fully written buffers, and update the indexes of the partially written buffer
                        input.RemoveBytes(writtenBytes);
                    }

                    if (!done)
                    {
                        IList<ArraySegment<byte>> asyncBufferList = bufferList;
                        if (object.ReferenceEquals(sharedBufferList, asyncBufferList))
                        {
                            asyncBufferList = sharedBufferList.ToArray(); // move out of shared list that will be reused which could corrupt buffers still pending update
                        }
                        var asyncOperation = PrepareWriteOperation(asyncBufferList);

                        // Not all buffers were written out completely
                        if (IncompleteWrite(true, asyncOperation))
                        {
                            break;
                        }
                    }
                }
            }
            finally
            {
                // Prepare the list for reuse
                sharedBufferList?.Clear();
            }
        }

        List<ArraySegment<byte>> AdjustBufferList(long localWrittenBytes, List<ArraySegment<byte>> bufferList)
        {
            var adjusted = new List<ArraySegment<byte>>(bufferList.Count);
            foreach (ArraySegment<byte> buffer in bufferList)
            {
                if (localWrittenBytes > 0)
                {
                    long leftBytes = localWrittenBytes - buffer.Count;
                    if (leftBytes < 0)
                    {
                        int offset = buffer.Offset + (int)localWrittenBytes;
                        int count = -(int)leftBytes;
                        adjusted.Add(new ArraySegment<byte>(buffer.Array, offset, count));
                        localWrittenBytes = 0;
                    }
                    else
                    {
                        localWrittenBytes = leftBytes;
                    }
                }
                else
                {
                    adjusted.Add(buffer);
                }
            }
            return adjusted;
        }

        //protected override IChannelUnsafe NewUnsafe() => new TcpSocketChannelUnsafe(this); ## 苦竹 屏蔽 ##
    }
}
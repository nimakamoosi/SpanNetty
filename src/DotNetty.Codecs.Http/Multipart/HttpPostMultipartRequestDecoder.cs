﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Codecs.Http.Multipart
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using DotNetty.Buffers;
    using DotNetty.Common;
    using DotNetty.Common.Utilities;

    /// <summary>
    /// This decoder will decode Body and can handle POST BODY.
    /// You <c>MUST</c> call <see cref="Destroy"/> after completion to release all resources.
    /// </summary>
    public class HttpPostMultipartRequestDecoder : IInterfaceHttpPostRequestDecoder
    {
        // Factory used to create InterfaceHttpData
        readonly IHttpDataFactory factory;

        // Request to decode
        readonly IHttpRequest request;

        // Default charset to use
        Encoding charset;

        // Does the last chunk already received
        bool isLastChunk;

        // HttpDatas from Body
        readonly List<IInterfaceHttpData> bodyListHttpData = new List<IInterfaceHttpData>();

        // HttpDatas as Map from Body
        readonly Dictionary<AsciiString, List<IInterfaceHttpData>> bodyMapHttpData = new Dictionary<AsciiString, List<IInterfaceHttpData>>(AsciiStringComparer.IgnoreCase);

        // The current channelBuffer
        IByteBuffer undecodedChunk;

        // Body HttpDatas current position
        int bodyListHttpDataRank;

        // If multipart, this is the boundary for the global multipart
        ICharSequence multipartDataBoundary;

        // If multipart, there could be internal multiparts (mixed) to the global
        // multipart. Only one level is allowed.
        ICharSequence multipartMixedBoundary;

        // Current getStatus
        MultiPartStatus currentStatus = MultiPartStatus.Notstarted;

        // Used in Multipart
        Dictionary<AsciiString, IAttribute> currentFieldAttributes;

        // The current FileUpload that is currently in decode process
        IFileUpload currentFileUpload;

        // The current Attribute that is currently in decode process
        IAttribute currentAttribute;

        bool destroyed;

        int discardThreshold = HttpPostRequestDecoder.DefaultDiscardThreshold;

        public HttpPostMultipartRequestDecoder(IHttpRequest request)
            : this(new DefaultHttpDataFactory(DefaultHttpDataFactory.MinSize), request, HttpConstants.DefaultEncoding)
        {
        }

        public HttpPostMultipartRequestDecoder(IHttpDataFactory factory, IHttpRequest request)
            : this(factory, request, HttpConstants.DefaultEncoding)
        {
        }

        public HttpPostMultipartRequestDecoder(IHttpDataFactory factory, IHttpRequest request, Encoding charset)
        {
            if (request is null) { ThrowHelper.ThrowArgumentNullException(ExceptionArgument.request); }
            if (charset is null) { ThrowHelper.ThrowArgumentNullException(ExceptionArgument.charset); }
            if (factory is null) { ThrowHelper.ThrowArgumentNullException(ExceptionArgument.factory); }

            this.factory = factory;
            this.request = request;
            this.charset = charset;

            // Fill default values
            this.SetMultipart(this.request.Headers.Get(HttpHeaderNames.ContentType, null));
            if (request is IHttpContent content)
            {
                // Offer automatically if the given request is als type of HttpContent
                // See #1089
                _ = this.Offer(content);
            }
            else
            {
                this.undecodedChunk = ArrayPooled.Buffer();
                this.ParseBody();
            }
        }

        void SetMultipart(ICharSequence contentType)
        {
            ICharSequence[] dataBoundary = HttpPostRequestDecoder.GetMultipartDataBoundary(contentType);
            if (dataBoundary is object)
            {
                this.multipartDataBoundary = new AsciiString(dataBoundary[0]);
                if ((uint)dataBoundary.Length > 1u && dataBoundary[1] is object)
                {
                    this.charset = Encoding.GetEncoding(dataBoundary[1].ToString());
                }
            }
            else
            {
                this.multipartDataBoundary = null;
            }
            this.currentStatus = MultiPartStatus.HeaderDelimiter;
        }

        void CheckDestroyed()
        {
            if (this.destroyed)
            {
                ThrowHelper.ThrowInvalidOperationException_CheckDestroyed<HttpPostMultipartRequestDecoder>();
            }
        }

        public bool IsMultipart
        {
            get
            {
                this.CheckDestroyed();
                return true;
            }
        }

        public int DiscardThreshold
        {
            get => this.discardThreshold;
            set
            {
                if (value < 0) { ThrowHelper.ThrowArgumentException_PositiveOrZero(value, ExceptionArgument.value); }
                this.discardThreshold = value;
            }
        }

        public List<IInterfaceHttpData> GetBodyHttpDatas()
        {
            this.CheckDestroyed();

            if (!this.isLastChunk)
            {
                ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.HttpPostMultipartRequestDecoder);
            }
            return this.bodyListHttpData;
        }

        public List<IInterfaceHttpData> GetBodyHttpDatas(AsciiString name)
        {
            this.CheckDestroyed();

            if (!this.isLastChunk)
            {
                ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.HttpPostMultipartRequestDecoder);
            }
            return this.bodyMapHttpData[name];
        }

        public IInterfaceHttpData GetBodyHttpData(AsciiString name)
        {
            this.CheckDestroyed();

            if (!this.isLastChunk)
            {
                ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.HttpPostMultipartRequestDecoder);
            }
            if (this.bodyMapHttpData.TryGetValue(name, out List<IInterfaceHttpData> list))
            {
                return list[0];
            }
            return null;
        }

        public IInterfaceHttpPostRequestDecoder Offer(IHttpContent content)
        {
            this.CheckDestroyed();

            // Maybe we should better not copy here for performance reasons but this will need
            // more care by the caller to release the content in a correct manner later
            // So maybe something to optimize on a later stage
            IByteBuffer buf = content.Content;
            if (this.undecodedChunk is null)
            {
                this.undecodedChunk = buf.Copy();
            }
            else
            {
                _ = this.undecodedChunk.WriteBytes(buf);
            }
            if (content is ILastHttpContent)
            {
                this.isLastChunk = true;
            }
            this.ParseBody();
            if (this.undecodedChunk is object
                && this.undecodedChunk.WriterIndex > this.discardThreshold)
            {
                _ = this.undecodedChunk.DiscardReadBytes();
            }
            return this;
        }

        public bool HasNext
        {
            get
            {
                this.CheckDestroyed();

                if (this.currentStatus == MultiPartStatus.Epilogue)
                {
                    // OK except if end of list
                    if (this.bodyListHttpDataRank >= this.bodyListHttpData.Count)
                    {
                        ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.HttpPostMultipartRequestDecoder);
                    }
                }
                return (uint)this.bodyListHttpData.Count > 0u && this.bodyListHttpDataRank < this.bodyListHttpData.Count;
            }
        }

        public IInterfaceHttpData Next()
        {
            this.CheckDestroyed();

            return this.HasNext
                ? this.bodyListHttpData[this.bodyListHttpDataRank++]
                : null;
        }

        public IInterfaceHttpData CurrentPartialHttpData
        {
            get
            {
                if (this.currentFileUpload is object)
                {
                    return this.currentFileUpload;
                }
                else
                {
                    return this.currentAttribute;
                }
            }
        }

        void ParseBody()
        {
            if (this.currentStatus == MultiPartStatus.PreEpilogue
                || this.currentStatus == MultiPartStatus.Epilogue)
            {
                if (this.isLastChunk)
                {
                    this.currentStatus = MultiPartStatus.Epilogue;
                }
                return;
            }

            this.ParseBodyMultipart();
        }

        protected void AddHttpData(IInterfaceHttpData data)
        {
            if (data is null)
            {
                return;
            }
            var name = new AsciiString(data.Name);
            if (!this.bodyMapHttpData.TryGetValue(name, out List<IInterfaceHttpData> datas))
            {
                datas = new List<IInterfaceHttpData>(1);
                this.bodyMapHttpData.Add(name, datas);
            }
            datas.Add(data);
            this.bodyListHttpData.Add(data);
        }

        void ParseBodyMultipart()
        {
            if (this.undecodedChunk is null
                || 0u >= (uint)this.undecodedChunk.ReadableBytes)
            {
                // nothing to decode
                return;
            }

            IInterfaceHttpData data = this.DecodeMultipart(this.currentStatus);
            while (data is object)
            {
                this.AddHttpData(data);
                if (this.currentStatus == MultiPartStatus.PreEpilogue
                    || this.currentStatus == MultiPartStatus.Epilogue)
                {
                    break;
                }

                data = this.DecodeMultipart(this.currentStatus);
            }
        }

        IInterfaceHttpData DecodeMultipart(MultiPartStatus state)
        {
            switch (state)
            {
                case MultiPartStatus.Notstarted:
                    ThrowHelper.ThrowErrorDataDecoderException_GetStatus(); return null;
                case MultiPartStatus.Preamble:
                    // Content-type: multipart/form-data, boundary=AaB03x
                    ThrowHelper.ThrowErrorDataDecoderException_GetStatus(); return null;
                case MultiPartStatus.HeaderDelimiter:
                    {
                        // --AaB03x or --AaB03x--
                        return this.FindMultipartDelimiter(this.multipartDataBoundary, MultiPartStatus.Disposition,
                            MultiPartStatus.PreEpilogue);
                    }
                case MultiPartStatus.Disposition:
                    {
                        // content-disposition: form-data; name="field1"
                        // content-disposition: form-data; name="pics"; filename="file1.txt"
                        // and other immediate values like
                        // Content-type: image/gif
                        // Content-Type: text/plain
                        // Content-Type: text/plain; charset=ISO-8859-1
                        // Content-Transfer-Encoding: binary
                        // The following line implies a change of mode (mixed mode)
                        // Content-type: multipart/mixed, boundary=BbC04y
                        return this.FindMultipartDisposition();
                    }
                case MultiPartStatus.Field:
                    {
                        // Now get value according to Content-Type and Charset
                        Encoding localCharset = null;
                        if (this.currentFieldAttributes.TryGetValue(HttpHeaderValues.Charset, out IAttribute charsetAttribute))
                        {
                            try
                            {
                                localCharset = Encoding.GetEncoding(charsetAttribute.Value);
                            }
                            catch (IOException e)
                            {
                                ThrowHelper.ThrowErrorDataDecoderException(e);
                            }
                            catch (ArgumentException e)
                            {
                                ThrowHelper.ThrowErrorDataDecoderException(e);
                            }
                        }
                        _ = this.currentFieldAttributes.TryGetValue(HttpHeaderValues.Name, out IAttribute nameAttribute);
                        if (this.currentAttribute is null)
                        {
                            _ = this.currentFieldAttributes.TryGetValue(HttpHeaderNames.ContentLength, out IAttribute lengthAttribute);
                            long size;
                            try
                            {
                                size = lengthAttribute is object ? long.Parse(lengthAttribute.Value) : 0L;
                            }
                            catch (IOException e)
                            {
                                ThrowHelper.ThrowErrorDataDecoderException(e); size = 0L;
                            }
                            catch (FormatException)
                            {
                                size = 0L;
                            }
                            try
                            {
                                if (nameAttribute is null)
                                {
                                    ThrowHelper.ThrowErrorDataDecoderException_Attr();
                                }
                                if (size > 0)
                                {
                                    this.currentAttribute = this.factory.CreateAttribute(this.request,
                                        CleanString(nameAttribute.Value).ToString(), size);
                                }
                                else
                                {
                                    this.currentAttribute = this.factory.CreateAttribute(this.request,
                                        CleanString(nameAttribute.Value).ToString());
                                }
                            }
                            catch (ArgumentException e)
                            {
                                ThrowHelper.ThrowErrorDataDecoderException(e);
                            }
                            catch (IOException e)
                            {
                                ThrowHelper.ThrowErrorDataDecoderException(e);
                            }
                            if (localCharset is object)
                            {
                                this.currentAttribute.Charset = localCharset;
                            }
                        }
                        // load data
                        if (!LoadDataMultipart(this.undecodedChunk, this.multipartDataBoundary, this.currentAttribute))
                        {
                            // Delimiter is not found. Need more chunks.
                            return null;
                        }
                        IAttribute finalAttribute = this.currentAttribute;
                        this.currentAttribute = null;
                        this.currentFieldAttributes = null;
                        // ready to load the next one
                        this.currentStatus = MultiPartStatus.HeaderDelimiter;
                        return finalAttribute;
                    }
                case MultiPartStatus.Fileupload:
                    {
                        // eventually restart from existing FileUpload
                        return this.GetFileUpload(this.multipartDataBoundary);
                    }
                case MultiPartStatus.MixedDelimiter:
                    {
                        // --AaB03x or --AaB03x--
                        // Note that currentFieldAttributes exists
                        return this.FindMultipartDelimiter(this.multipartMixedBoundary, MultiPartStatus.MixedDisposition,
                            MultiPartStatus.HeaderDelimiter);
                    }
                case MultiPartStatus.MixedDisposition:
                    {
                        return this.FindMultipartDisposition();
                    }
                case MultiPartStatus.MixedFileUpload:
                    {
                        // eventually restart from existing FileUpload
                        return this.GetFileUpload(this.multipartMixedBoundary);
                    }
                case MultiPartStatus.PreEpilogue:
                case MultiPartStatus.Epilogue:
                    return null;
                default:
                    ThrowHelper.ThrowErrorDataDecoderException_ReachHere(); return null;
            }
        }

        static void SkipControlCharacters(IByteBuffer undecodedChunk)
        {
            if (!undecodedChunk.HasArray)
            {
                try
                {
                    SkipControlCharactersStandard(undecodedChunk);
                }
                catch (IndexOutOfRangeException e)
                {
                    ThrowHelper.ThrowNotEnoughDataDecoderException(e);
                }
                return;
            }
            var sao = new HttpPostBodyUtil.SeekAheadOptimize(undecodedChunk);
            while (sao.Pos < sao.Limit)
            {
                char c = (char)sao.Bytes[sao.Pos++];
                if (!CharUtil.IsISOControl(c) && !char.IsWhiteSpace(c))
                {
                    sao.SetReadPosition(1);
                    return;
                }
            }
            ThrowHelper.ThrowNotEnoughDataDecoderException_AccessOutOfBounds();
        }

        static void SkipControlCharactersStandard(IByteBuffer undecodedChunk)
        {
            while (true)
            {
                char c = (char)undecodedChunk.ReadByte();
                if (!CharUtil.IsISOControl(c) && !char.IsWhiteSpace(c))
                {
                    _ = undecodedChunk.SetReaderIndex(undecodedChunk.ReaderIndex - 1);
                    break;
                }
            }
        }

        IInterfaceHttpData FindMultipartDelimiter(ICharSequence delimiter, MultiPartStatus dispositionStatus,
            MultiPartStatus closeDelimiterStatus)
        {
            // --AaB03x or --AaB03x--
            int readerIndex = this.undecodedChunk.ReaderIndex;
            try
            {
                SkipControlCharacters(this.undecodedChunk);
            }
            catch (NotEnoughDataDecoderException)
            {
                _ = this.undecodedChunk.SetReaderIndex(readerIndex);
                return null;
            }
            _ = this.SkipOneLine();
            StringBuilderCharSequence newline;
            try
            {
                newline = ReadDelimiter(this.undecodedChunk, delimiter);
            }
            catch (NotEnoughDataDecoderException)
            {
                _ = this.undecodedChunk.SetReaderIndex(readerIndex);
                return null;
            }
            if (newline.Equals(delimiter))
            {
                this.currentStatus = dispositionStatus;
                return this.DecodeMultipart(dispositionStatus);
            }
            if (AsciiString.ContentEquals(newline, new StringCharSequence(delimiter.ToString() + "--")))
            {
                // CloseDelimiter or MIXED CloseDelimiter found
                this.currentStatus = closeDelimiterStatus;
                if (this.currentStatus == MultiPartStatus.HeaderDelimiter)
                {
                    // MixedCloseDelimiter
                    // end of the Mixed part
                    this.currentFieldAttributes = null;
                    return this.DecodeMultipart(MultiPartStatus.HeaderDelimiter);
                }
                return null;
            }
            _ = this.undecodedChunk.SetReaderIndex(readerIndex);
            ThrowHelper.ThrowErrorDataDecoderException_NoMultipartDelimiterFound(); return null;
        }

        IInterfaceHttpData FindMultipartDisposition()
        {
            int readerIndex = this.undecodedChunk.ReaderIndex;
            if (this.currentStatus == MultiPartStatus.Disposition)
            {
                this.currentFieldAttributes = new Dictionary<AsciiString, IAttribute>(AsciiStringComparer.IgnoreCase);
            }
            // read many lines until empty line with newline found! Store all data
            while (!this.SkipOneLine())
            {
                StringCharSequence newline;
                try
                {
                    SkipControlCharacters(this.undecodedChunk);
                    newline = ReadLine(this.undecodedChunk, this.charset);
                }
                catch (NotEnoughDataDecoderException)
                {
                    _ = this.undecodedChunk.SetReaderIndex(readerIndex);
                    return null;
                }
                ICharSequence[] contents = SplitMultipartHeader(newline);
                if (HttpHeaderNames.ContentDisposition.ContentEqualsIgnoreCase(contents[0]))
                {
                    bool checkSecondArg;
                    if (this.currentStatus == MultiPartStatus.Disposition)
                    {
                        checkSecondArg = HttpHeaderValues.FormData.ContentEqualsIgnoreCase(contents[1]);
                    }
                    else
                    {
                        checkSecondArg = HttpHeaderValues.Attachment.ContentEqualsIgnoreCase(contents[1])
                            || HttpHeaderValues.File.ContentEqualsIgnoreCase(contents[1]);
                    }
                    if (checkSecondArg)
                    {
                        // read next values and store them in the map as Attribute
                        for (int i = 2; i < contents.Length; i++)
                        {
                            ICharSequence[] values = CharUtil.Split(contents[i], '=');
                            IAttribute attribute = null;
                            try
                            {
                                attribute = this.GetContentDispositionAttribute(values);
                            }
                            catch (ArgumentNullException e)
                            {
                                ThrowHelper.ThrowErrorDataDecoderException(e);
                            }
                            catch (ArgumentException e)
                            {
                                ThrowHelper.ThrowErrorDataDecoderException(e);
                            }
                            this.currentFieldAttributes.Add(new AsciiString(attribute.Name), attribute);
                        }
                    }
                }
                else if (HttpHeaderNames.ContentTransferEncoding.ContentEqualsIgnoreCase(contents[0]))
                {
                    IAttribute attribute = null;
                    try
                    {
                        attribute = this.factory.CreateAttribute(this.request, HttpHeaderNames.ContentTransferEncoding.ToString(),
                            CleanString(contents[1]).ToString());
                    }
                    catch (ArgumentNullException e)
                    {
                        ThrowHelper.ThrowErrorDataDecoderException(e);
                    }
                    catch (ArgumentException e)
                    {
                        ThrowHelper.ThrowErrorDataDecoderException(e);
                    }

                    this.currentFieldAttributes.Add(HttpHeaderNames.ContentTransferEncoding, attribute);
                }
                else if (HttpHeaderNames.ContentLength.ContentEqualsIgnoreCase(contents[0]))
                {
                    IAttribute attribute = null;
                    try
                    {
                        attribute = this.factory.CreateAttribute(this.request, HttpHeaderNames.ContentLength.ToString(),
                            CleanString(contents[1]).ToString());
                    }
                    catch (ArgumentNullException e)
                    {
                        ThrowHelper.ThrowErrorDataDecoderException(e);
                    }
                    catch (ArgumentException e)
                    {
                        ThrowHelper.ThrowErrorDataDecoderException(e);
                    }

                    this.currentFieldAttributes.Add(HttpHeaderNames.ContentLength, attribute);
                }
                else if (HttpHeaderNames.ContentType.ContentEqualsIgnoreCase(contents[0]))
                {
                    // Take care of possible "multipart/mixed"
                    if (HttpHeaderValues.MultipartMixed.ContentEqualsIgnoreCase(contents[1]))
                    {
                        if (this.currentStatus == MultiPartStatus.Disposition)
                        {
                            ICharSequence values = contents[2].SubstringAfter('=');
                            this.multipartMixedBoundary = new StringCharSequence("--" + values.ToString());
                            this.currentStatus = MultiPartStatus.MixedDelimiter;
                            return this.DecodeMultipart(MultiPartStatus.MixedDelimiter);
                        }
                        else
                        {
                            ThrowHelper.ThrowErrorDataDecoderException_MixedMultipartFound();
                        }
                    }
                    else
                    {
                        for (int i = 1; i < contents.Length; i++)
                        {
                            ICharSequence charsetHeader = HttpHeaderValues.Charset;
                            if (contents[i].RegionMatchesIgnoreCase(0, charsetHeader, 0, charsetHeader.Count))
                            {
                                ICharSequence values = contents[i].SubstringAfter('=');
                                IAttribute attribute = null;
                                try
                                {
                                    attribute = this.factory.CreateAttribute(this.request, charsetHeader.ToString(), CleanString(values).ToString());
                                }
                                catch (ArgumentNullException e)
                                {
                                    ThrowHelper.ThrowErrorDataDecoderException(e);
                                }
                                catch (ArgumentException e)
                                {
                                    ThrowHelper.ThrowErrorDataDecoderException(e);
                                }
                                this.currentFieldAttributes.Add(HttpHeaderValues.Charset, attribute);
                            }
                            else
                            {
                                IAttribute attribute = null;
                                ICharSequence name = null;
                                try
                                {
                                    name = CleanString(contents[0]);
                                    attribute = this.factory.CreateAttribute(this.request,
                                        name.ToString(), contents[i].ToString());
                                }
                                catch (ArgumentNullException e)
                                {
                                    ThrowHelper.ThrowErrorDataDecoderException(e);
                                }
                                catch (ArgumentException e)
                                {
                                    ThrowHelper.ThrowErrorDataDecoderException(e);
                                }
                                this.currentFieldAttributes.Add(new AsciiString(name), attribute);
                            }
                        }
                    }
                }
            }
            // Is it a FileUpload
            _ = this.currentFieldAttributes.TryGetValue(HttpHeaderValues.FileName, out IAttribute filenameAttribute);
            if (this.currentStatus == MultiPartStatus.Disposition)
            {
                if (filenameAttribute is object)
                {
                    // FileUpload
                    this.currentStatus = MultiPartStatus.Fileupload;
                    // do not change the buffer position
                    return this.DecodeMultipart(MultiPartStatus.Fileupload);
                }
                else
                {
                    // Field
                    this.currentStatus = MultiPartStatus.Field;
                    // do not change the buffer position
                    return this.DecodeMultipart(MultiPartStatus.Field);
                }
            }
            else
            {
                if (filenameAttribute is object)
                {
                    // FileUpload
                    this.currentStatus = MultiPartStatus.MixedFileUpload;
                    // do not change the buffer position
                    return this.DecodeMultipart(MultiPartStatus.MixedFileUpload);
                }
                else
                {
                    // Field is not supported in MIXED mode
                    ThrowHelper.ThrowErrorDataDecoderException_FileName(); return null;
                }
            }
        }

        static readonly AsciiString FilenameEncoded = AsciiString.Cached(HttpHeaderValues.FileName.ToString() + '*');

        IAttribute GetContentDispositionAttribute(params ICharSequence[] values)
        {
            ICharSequence name = CleanString(values[0]);
            ICharSequence value = values[1];

            // Filename can be token, quoted or encoded. See https://tools.ietf.org/html/rfc5987
            if (HttpHeaderValues.FileName.ContentEquals(name))
            {
                // Value is quoted or token. Strip if quoted:
                int last = value.Count - 1;
                if (last > 0
                    && value[0] == HttpConstants.DoubleQuote
                    && value[last] == HttpConstants.DoubleQuote)
                {
                    value = value.SubSequence(1, last);
                }
            }
            else if (FilenameEncoded.ContentEquals(name))
            {
                try
                {
                    name = HttpHeaderValues.FileName;
                    string[] split = value.ToString().Split(new[] { '\'' }, 3);
                    value = new StringCharSequence(
                        QueryStringDecoder.DecodeComponent(split[2], Encoding.GetEncoding(split[0])));
                }
                catch (IndexOutOfRangeException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
                catch (ArgumentException e) // Invalid encoding
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
            }
            else
            {
                // otherwise we need to clean the value
                value = CleanString(value);
            }
            return this.factory.CreateAttribute(this.request, name.ToString(), value.ToString());
        }

        protected IInterfaceHttpData GetFileUpload(ICharSequence delimiter)
        {
            // eventually restart from existing FileUpload
            // Now get value according to Content-Type and Charset
            this.currentFieldAttributes.TryGetValue(HttpHeaderNames.ContentTransferEncoding, out IAttribute encodingAttribute);
            Encoding localCharset = this.charset;
            // Default
            HttpPostBodyUtil.TransferEncodingMechanism mechanism = HttpPostBodyUtil.TransferEncodingMechanism.Bit7;
            if (encodingAttribute is object)
            {
                string code = null;
                try
                {
                    code = encodingAttribute.Value.ToLowerInvariant();
                }
                catch (IOException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
                if (string.Equals(code, HttpPostBodyUtil.TransferEncodingMechanism.Bit7.Value
#if NETCOREAPP_3_0_GREATER || NETSTANDARD_2_0_GREATER
                    ))
#else
                    , StringComparison.Ordinal))
#endif
                {
                    localCharset = Encoding.ASCII;
                }
                else if (string.Equals(code, HttpPostBodyUtil.TransferEncodingMechanism.Bit8.Value
#if NETCOREAPP_3_0_GREATER || NETSTANDARD_2_0_GREATER
                    ))
#else
                    , StringComparison.Ordinal))
#endif
                {
                    localCharset = Encoding.UTF8;
                    mechanism = HttpPostBodyUtil.TransferEncodingMechanism.Bit8;
                }
                else if (string.Equals(code, HttpPostBodyUtil.TransferEncodingMechanism.Binary.Value
#if NETCOREAPP_3_0_GREATER || NETSTANDARD_2_0_GREATER
                    ))
#else
                    , StringComparison.Ordinal))
#endif
                {
                    // no real charset, so let the default
                    mechanism = HttpPostBodyUtil.TransferEncodingMechanism.Binary;
                }
                else
                {
                    ThrowHelper.ThrowErrorDataDecoderException_TransferEncoding(code);
                }
            }
            if (this.currentFieldAttributes.TryGetValue(HttpHeaderValues.Charset, out IAttribute charsetAttribute))
            {
                try
                {
                    localCharset = Encoding.GetEncoding(charsetAttribute.Value);
                }
                catch (IOException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
                catch (ArgumentException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
            }
            if (this.currentFileUpload is null)
            {
                this.currentFieldAttributes.TryGetValue(HttpHeaderValues.FileName, out IAttribute filenameAttribute);
                this.currentFieldAttributes.TryGetValue(HttpHeaderValues.Name, out IAttribute nameAttribute);
                this.currentFieldAttributes.TryGetValue(HttpHeaderNames.ContentType, out IAttribute contentTypeAttribute);
                this.currentFieldAttributes.TryGetValue(HttpHeaderNames.ContentLength, out IAttribute lengthAttribute);
                long size;
                try
                {
                    size = lengthAttribute is object ? long.Parse(lengthAttribute.Value) : 0L;
                }
                catch (IOException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e); size = 0L;
                }
                catch (FormatException)
                {
                    size = 0L;
                }
                try
                {
                    string contentType;
                    if (contentTypeAttribute is object)
                    {
                        contentType = contentTypeAttribute.Value;
                    }
                    else
                    {
                        contentType = HttpPostBodyUtil.DefaultBinaryContentType;
                    }
                    if (nameAttribute is null)
                    {
                        ThrowHelper.ThrowErrorDataDecoderException_NameAttr();
                    }
                    if (filenameAttribute is null)
                    {
                        ThrowHelper.ThrowErrorDataDecoderException_FileNameAttr();
                    }
                    this.currentFileUpload = this.factory.CreateFileUpload(this.request,
                        CleanString(nameAttribute.Value).ToString(), CleanString(filenameAttribute.Value).ToString(),
                        contentType, mechanism.Value, localCharset,
                        size);
                }
                catch (ArgumentNullException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
                catch (ArgumentException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
                catch (IOException e)
                {
                    ThrowHelper.ThrowErrorDataDecoderException(e);
                }
            }
            // load data as much as possible
            if (!LoadDataMultipart(this.undecodedChunk, delimiter, this.currentFileUpload))
            {
                // Delimiter is not found. Need more chunks.
                return null;
            }
            if (this.currentFileUpload.IsCompleted)
            {
                // ready to load the next one
                if (this.currentStatus == MultiPartStatus.Fileupload)
                {
                    this.currentStatus = MultiPartStatus.HeaderDelimiter;
                    this.currentFieldAttributes = null;
                }
                else
                {
                    this.currentStatus = MultiPartStatus.MixedDelimiter;
                    this.CleanMixedAttributes();
                }
                IFileUpload fileUpload = this.currentFileUpload;
                this.currentFileUpload = null;
                return fileUpload;
            }

            // do not change the buffer position
            // since some can be already saved into FileUpload
            // So do not change the currentStatus
            return null;
        }

        public void Destroy()
        {
            // Release all data items, including those not yet pulled
            this.CleanFiles();
            this.destroyed = true;

            if (this.undecodedChunk is object && this.undecodedChunk.ReferenceCount > 0)
            {
                _ = this.undecodedChunk.Release();
                this.undecodedChunk = null;
            }
        }

        public void CleanFiles()
        {
            this.CheckDestroyed();
            this.factory.CleanRequestHttpData(this.request);
        }

        public void RemoveHttpDataFromClean(IInterfaceHttpData data)
        {
            this.CheckDestroyed();

            this.factory.RemoveHttpDataFromClean(this.request, data);
        }


        // Remove all Attributes that should be cleaned between two FileUpload in
        // Mixed mode
        void CleanMixedAttributes()
        {
            _ = this.currentFieldAttributes.Remove(HttpHeaderValues.Charset);
            _ = this.currentFieldAttributes.Remove(HttpHeaderNames.ContentLength);
            _ = this.currentFieldAttributes.Remove(HttpHeaderNames.ContentTransferEncoding);
            _ = this.currentFieldAttributes.Remove(HttpHeaderNames.ContentType);
            _ = this.currentFieldAttributes.Remove(HttpHeaderValues.FileName);
        }

        static StringCharSequence ReadLineStandard(IByteBuffer undecodedChunk, Encoding charset)
        {
            int readerIndex = undecodedChunk.ReaderIndex;
            IByteBuffer line = ArrayPooled.Buffer(64);
            try
            {
                while (undecodedChunk.IsReadable())
                {
                    byte nextByte = undecodedChunk.ReadByte();
                    if (nextByte == HttpConstants.CarriageReturn)
                    {
                        // check but do not changed readerIndex
                        nextByte = undecodedChunk.GetByte(undecodedChunk.ReaderIndex);
                        if (nextByte == HttpConstants.LineFeed)
                        {
                            // force read
                            _ = undecodedChunk.ReadByte();
                            return new StringCharSequence(line.ToString(charset));
                        }
                        else
                        {
                            // Write CR (not followed by LF)
                            _ = line.WriteByte(HttpConstants.CarriageReturn);
                        }
                    }
                    else if (nextByte == HttpConstants.LineFeed)
                    {
                        return new StringCharSequence(line.ToString(charset));
                    }
                    else
                    {
                        _ = line.WriteByte(nextByte);
                    }
                }
            }
            catch (IndexOutOfRangeException e)
            {
                _ = undecodedChunk.SetReaderIndex(readerIndex);
                ThrowHelper.ThrowNotEnoughDataDecoderException(e);
            }
            finally { _ = line.Release(); }
            _ = undecodedChunk.SetReaderIndex(readerIndex);
            return ThrowHelper.ThrowNotEnoughDataDecoderException_ReadLineStandard();
        }

        static StringCharSequence ReadLine(IByteBuffer undecodedChunk, Encoding charset)
        {
            if (!undecodedChunk.HasArray)
            {
                return ReadLineStandard(undecodedChunk, charset);
            }
            var sao = new HttpPostBodyUtil.SeekAheadOptimize(undecodedChunk);
            int readerIndex = undecodedChunk.ReaderIndex;
            IByteBuffer line = ArrayPooled.Buffer(64);
            try
            {
                while (sao.Pos < sao.Limit)
                {
                    byte nextByte = sao.Bytes[sao.Pos++];
                    if (nextByte == HttpConstants.CarriageReturn)
                    {
                        if (sao.Pos < sao.Limit)
                        {
                            nextByte = sao.Bytes[sao.Pos++];
                            if (nextByte == HttpConstants.LineFeed)
                            {
                                sao.SetReadPosition(0);
                                return new StringCharSequence(line.ToString(charset));
                            }
                            else
                            {
                                // Write CR (not followed by LF)
                                sao.Pos--;
                                _ = line.WriteByte(HttpConstants.CarriageReturn);
                            }
                        }
                        else
                        {
                            _ = line.WriteByte(nextByte);
                        }
                    }
                    else if (nextByte == HttpConstants.LineFeed)
                    {
                        sao.SetReadPosition(0);
                        return new StringCharSequence(line.ToString(charset));
                    }
                    else
                    {
                        _ = line.WriteByte(nextByte);
                    }
                }
            }
            catch (IndexOutOfRangeException e)
            {
                _ = undecodedChunk.SetReaderIndex(readerIndex);
                ThrowHelper.ThrowNotEnoughDataDecoderException(e);
            }
            finally
            {
                _ = line.Release();
            }
            _ = undecodedChunk.SetReaderIndex(readerIndex);
            return ThrowHelper.ThrowNotEnoughDataDecoderException_ReadLine();
        }

        static StringBuilderCharSequence ReadDelimiterStandard(IByteBuffer undecodedChunk, ICharSequence delimiter)
        {
            int readerIndex = undecodedChunk.ReaderIndex;
            try
            {
                var sb = new StringBuilderCharSequence(64);
                int delimiterPos = 0;
                int len = delimiter.Count;
                while (undecodedChunk.IsReadable() && delimiterPos < len)
                {
                    byte nextByte = undecodedChunk.ReadByte();
                    if (nextByte == delimiter[delimiterPos])
                    {
                        delimiterPos++;
                        sb.Append((char)nextByte);
                    }
                    else
                    {
                        // delimiter not found so break here !
                        _ = undecodedChunk.SetReaderIndex(readerIndex);
                        ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiterStandard);
                    }
                }
                // Now check if either opening delimiter or closing delimiter
                if (undecodedChunk.IsReadable())
                {
                    byte nextByte = undecodedChunk.ReadByte();
                    switch (nextByte)
                    {
                        // first check for opening delimiter
                        case HttpConstants.CarriageReturn:
                            nextByte = undecodedChunk.ReadByte();
                            if (nextByte == HttpConstants.LineFeed)
                            {
                                return sb;
                            }
                            else
                            {
                                // error since CR must be followed by LF
                                // delimiter not found so break here !
                                _ = undecodedChunk.SetReaderIndex(readerIndex);
                                ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiterStandard);
                            }
                            break;

                        case HttpConstants.LineFeed:
                            return sb;

                        case HttpConstants.MinusSign:
                            sb.Append(HttpConstants.MinusSignChar);
                            // second check for closing delimiter
                            nextByte = undecodedChunk.ReadByte();
                            if (nextByte == HttpConstants.MinusSignChar)
                            {
                                sb.Append(HttpConstants.MinusSignChar);
                                // now try to find if CRLF or LF there
                                if (undecodedChunk.IsReadable())
                                {
                                    nextByte = undecodedChunk.ReadByte();
                                    if (nextByte == HttpConstants.CarriageReturn)
                                    {
                                        nextByte = undecodedChunk.ReadByte();
                                        if (nextByte == HttpConstants.LineFeed)
                                        {
                                            return sb;
                                        }
                                        else
                                        {
                                            // error CR without LF
                                            // delimiter not found so break here !
                                            _ = undecodedChunk.SetReaderIndex(readerIndex);
                                            ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiterStandard);
                                        }
                                    }
                                    else if (nextByte == HttpConstants.LineFeed)
                                    {
                                        return sb;
                                    }
                                    else
                                    {
                                        // No CRLF but ok however (Adobe Flash uploader)
                                        // minus 1 since we read one char ahead but
                                        // should not
                                        _ = undecodedChunk.SetReaderIndex(undecodedChunk.ReaderIndex - 1);
                                        return sb;
                                    }
                                }
                                // FIXME what do we do here?
                                // either considering it is fine, either waiting for
                                // more data to come?
                                // lets try considering it is fine...
                                return sb;
                            }
                            // only one '-' => not enough
                            // whatever now => error since incomplete
                            break;
                    }
                }
            }
            catch (IndexOutOfRangeException e)
            {
                _ = undecodedChunk.SetReaderIndex(readerIndex);
                ThrowHelper.ThrowNotEnoughDataDecoderException(e);
            }
            _ = undecodedChunk.SetReaderIndex(readerIndex);
            return ThrowHelper.ThrowNotEnoughDataDecoderException_ReadDelimiterStandard();
        }

        static StringBuilderCharSequence ReadDelimiter(IByteBuffer undecodedChunk, ICharSequence delimiter)
        {
            if (!undecodedChunk.HasArray)
            {
                return ReadDelimiterStandard(undecodedChunk, delimiter);
            }
            var sao = new HttpPostBodyUtil.SeekAheadOptimize(undecodedChunk);
            int readerIndex = undecodedChunk.ReaderIndex;
            int delimiterPos = 0;
            int len = delimiter.Count;
            try
            {
                var sb = new StringBuilderCharSequence(64);
                // check conformity with delimiter
                while (sao.Pos < sao.Limit && delimiterPos < len)
                {
                    byte nextByte = sao.Bytes[sao.Pos++];
                    if (nextByte == delimiter[delimiterPos])
                    {
                        delimiterPos++;
                        sb.Append((char)nextByte);
                    }
                    else
                    {
                        // delimiter not found so break here !
                        _ = undecodedChunk.SetReaderIndex(readerIndex);
                        ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiter);
                    }
                }
                // Now check if either opening delimiter or closing delimiter
                if (sao.Pos < sao.Limit)
                {
                    byte nextByte = sao.Bytes[sao.Pos++];
                    switch (nextByte)
                    {
                        case HttpConstants.CarriageReturn:
                            // first check for opening delimiter
                            if (sao.Pos < sao.Limit)
                            {
                                nextByte = sao.Bytes[sao.Pos++];
                                if (nextByte == HttpConstants.LineFeed)
                                {
                                    sao.SetReadPosition(0);
                                    return sb;
                                }
                                else
                                {
                                    // error CR without LF
                                    // delimiter not found so break here !
                                    _ = undecodedChunk.SetReaderIndex(readerIndex);
                                    ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiter);
                                }
                            }
                            else
                            {
                                // error since CR must be followed by LF
                                // delimiter not found so break here !
                                _ = undecodedChunk.SetReaderIndex(readerIndex);
                                ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiter);
                            }
                            break;

                        case HttpConstants.LineFeed:
                            // same first check for opening delimiter where LF used with
                            // no CR
                            sao.SetReadPosition(0);
                            return sb;

                        case HttpConstants.MinusSign:
                            sb.Append(HttpConstants.MinusSignChar);
                            // second check for closing delimiter
                            if (sao.Pos < sao.Limit)
                            {
                                nextByte = sao.Bytes[sao.Pos++];
                                if (nextByte == HttpConstants.MinusSignChar)
                                {
                                    sb.Append(HttpConstants.MinusSignChar);
                                    // now try to find if CRLF or LF there
                                    if (sao.Pos < sao.Limit)
                                    {
                                        nextByte = sao.Bytes[sao.Pos++];
                                        if (nextByte == HttpConstants.CarriageReturn)
                                        {
                                            if (sao.Pos < sao.Limit)
                                            {
                                                nextByte = sao.Bytes[sao.Pos++];
                                                if (nextByte == HttpConstants.LineFeed)
                                                {
                                                    sao.SetReadPosition(0);
                                                    return sb;
                                                }
                                                else
                                                {
                                                    // error CR without LF
                                                    // delimiter not found so break here !
                                                    _ = undecodedChunk.SetReaderIndex(readerIndex);
                                                    ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiter);
                                                }
                                            }
                                            else
                                            {
                                                // error CR without LF
                                                // delimiter not found so break here !
                                                _ = undecodedChunk.SetReaderIndex(readerIndex);
                                                ThrowHelper.ThrowNotEnoughDataDecoderException(ExceptionArgument.ReadDelimiter);
                                            }
                                        }
                                        else if (nextByte == HttpConstants.LineFeed)
                                        {
                                            sao.SetReadPosition(0);
                                            return sb;
                                        }
                                        else
                                        {
                                            // No CRLF but ok however (Adobe Flash
                                            // uploader)
                                            // minus 1 since we read one char ahead but
                                            // should not
                                            sao.SetReadPosition(1);
                                            return sb;
                                        }
                                    }
                                    // FIXME what do we do here?
                                    // either considering it is fine, either waiting for
                                    // more data to come?
                                    // lets try considering it is fine...
                                    sao.SetReadPosition(0);
                                    return sb;
                                }
                                // whatever now => error since incomplete
                                // only one '-' => not enough or whatever not enough
                                // element
                            }
                            break;
                    }
                }
            }
            catch (IndexOutOfRangeException e)
            {
                _ = undecodedChunk.SetReaderIndex(readerIndex);
                ThrowHelper.ThrowNotEnoughDataDecoderException(e);
            }
            _ = undecodedChunk.SetReaderIndex(readerIndex);
            return ThrowHelper.ThrowNotEnoughDataDecoderException_ReadDelimiter();
        }

        static bool LoadDataMultipartStandard(IByteBuffer undecodedChunk, ICharSequence delimiter, IHttpData httpData)
        {
            int startReaderIndex = undecodedChunk.ReaderIndex;
            int delimeterLength = delimiter.Count;
            int index = 0;
            int lastPosition = startReaderIndex;
            byte prevByte = HttpConstants.LineFeed;
            bool delimiterFound = false;
            while (undecodedChunk.IsReadable())
            {
                byte nextByte = undecodedChunk.ReadByte();
                // Check the delimiter
                if (prevByte == HttpConstants.LineFeed && nextByte == CharUtil.CodePointAt(delimiter, index))
                {
                    index++;
                    if (delimeterLength == index)
                    {
                        delimiterFound = true;
                        break;
                    }
                    continue;
                }
                lastPosition = undecodedChunk.ReaderIndex;
                if (nextByte == HttpConstants.LineFeed)
                {
                    index = 0;
                    lastPosition -= (prevByte == HttpConstants.CarriageReturn) ? 2 : 1;
                }
                prevByte = nextByte;
            }
            if (prevByte == HttpConstants.CarriageReturn)
            {
                lastPosition--;
            }
            IByteBuffer content = undecodedChunk.Copy(startReaderIndex, lastPosition - startReaderIndex);
            try
            {
                httpData.AddContent(content, delimiterFound);
            }
            catch (IOException e)
            {
                ThrowHelper.ThrowErrorDataDecoderException(e);
            }
            _ = undecodedChunk.SetReaderIndex(lastPosition);
            return delimiterFound;
        }

        static bool LoadDataMultipart(IByteBuffer undecodedChunk, ICharSequence delimiter, IHttpData httpData)
        {
            if (!undecodedChunk.HasArray)
            {
                return LoadDataMultipartStandard(undecodedChunk, delimiter, httpData);
            }
            var sao = new HttpPostBodyUtil.SeekAheadOptimize(undecodedChunk);
            int startReaderIndex = undecodedChunk.ReaderIndex;
            int delimeterLength = delimiter.Count;
            int index = 0;
            int lastRealPos = sao.Pos;
            byte prevByte = HttpConstants.LineFeed;
            bool delimiterFound = false;
            while (sao.Pos < sao.Limit)
            {
                byte nextByte = sao.Bytes[sao.Pos++];
                // Check the delimiter
                if (prevByte == HttpConstants.LineFeed && nextByte == CharUtil.CodePointAt(delimiter, index))
                {
                    index++;
                    if (delimeterLength == index)
                    {
                        delimiterFound = true;
                        break;
                    }
                    continue;
                }
                lastRealPos = sao.Pos;
                if (nextByte == HttpConstants.LineFeed)
                {
                    index = 0;
                    lastRealPos -= (prevByte == HttpConstants.CarriageReturn) ? 2 : 1;
                }
                prevByte = nextByte;
            }
            if (prevByte == HttpConstants.CarriageReturn)
            {
                lastRealPos--;
            }
            int lastPosition = sao.GetReadPosition(lastRealPos);
            IByteBuffer content = undecodedChunk.Copy(startReaderIndex, lastPosition - startReaderIndex);
            try
            {
                httpData.AddContent(content, delimiterFound);
            }
            catch (IOException e)
            {
                ThrowHelper.ThrowErrorDataDecoderException(e);
            }
            _ = undecodedChunk.SetReaderIndex(lastPosition);
            return delimiterFound;
        }

        static ICharSequence CleanString(string field) => CleanString(new StringCharSequence(field));

        static ICharSequence CleanString(ICharSequence field)
        {
            int size = field.Count;
            var sb = new StringBuilderCharSequence(size);
            for (int i = 0; i < size; i++)
            {
                char nextChar = field[i];
                switch (nextChar)
                {
                    case HttpConstants.ColonChar:  // Colon
                    case HttpConstants.CommaChar:  // Comma
                    case HttpConstants.EqualsSignChar:  // EqualsSign
                    case HttpConstants.SemicolonChar:  // Semicolon
                    case HttpConstants.HorizontalTabChar: // HorizontalTab
                        sb.Append(HttpConstants.HorizontalSpaceChar);
                        break;
                    case HttpConstants.DoubleQuoteChar:  // DoubleQuote
                        // nothing added, just removes it
                        break;
                    default:
                        sb.Append(nextChar);
                        break;
                }
            }
            return CharUtil.Trim(sb);
        }

        bool SkipOneLine()
        {
            if (!this.undecodedChunk.IsReadable())
            {
                return false;
            }
            byte nextByte = this.undecodedChunk.ReadByte();
            if (nextByte == HttpConstants.CarriageReturn)
            {
                if (!this.undecodedChunk.IsReadable())
                {
                    _ = this.undecodedChunk.SetReaderIndex(this.undecodedChunk.ReaderIndex - 1);
                    return false;
                }

                nextByte = this.undecodedChunk.ReadByte();
                if (nextByte == HttpConstants.LineFeed)
                {
                    return true;
                }

                _ = this.undecodedChunk.SetReaderIndex(this.undecodedChunk.ReaderIndex - 2);
                return false;
            }

            if (nextByte == HttpConstants.LineFeed)
            {
                return true;
            }
            _ = this.undecodedChunk.SetReaderIndex(this.undecodedChunk.ReaderIndex - 1);
            return false;
        }


        static ICharSequence[] SplitMultipartHeader(ICharSequence sb)
        {
            var headers = new List<ICharSequence>(1);
            int nameEnd;
            int colonEnd;
            int nameStart = HttpPostBodyUtil.FindNonWhitespace(sb, 0);
            for (nameEnd = nameStart; nameEnd < sb.Count; nameEnd++)
            {
                char ch = sb[nameEnd];
                if (ch == HttpConstants.ColonChar || char.IsWhiteSpace(ch))
                {
                    break;
                }
            }
            for (colonEnd = nameEnd; colonEnd < sb.Count; colonEnd++)
            {
                if (sb[colonEnd] == HttpConstants.ColonChar)
                {
                    colonEnd++;
                    break;
                }
            }
            int valueStart = HttpPostBodyUtil.FindNonWhitespace(sb, colonEnd);
            int valueEnd = HttpPostBodyUtil.FindEndOfString(sb);
            headers.Add(sb.SubSequence(nameStart, nameEnd));
            ICharSequence svalue = (valueStart >= valueEnd) ? AsciiString.Empty : sb.SubSequence(valueStart, valueEnd);
            ICharSequence[] values;
            if (svalue.IndexOf(HttpConstants.SemicolonChar) >= 0)
            {
                values = SplitMultipartHeaderValues(svalue);
            }
            else
            {
                values = CharUtil.Split(svalue, HttpConstants.CommaChar);
            }
            foreach (ICharSequence value in values)
            {
                headers.Add(CharUtil.Trim(value));
            }
            var array = new ICharSequence[headers.Count];
            for (int i = 0; i < headers.Count; i++)
            {
                array[i] = headers[i];
            }
            return array;
        }

        static ICharSequence[] SplitMultipartHeaderValues(ICharSequence svalue)
        {
            List<ICharSequence> values = InternalThreadLocalMap.Get().CharSequenceList(1);
            bool inQuote = false;
            bool escapeNext = false;
            int start = 0;
            for (int i = 0; i < svalue.Count; i++)
            {
                char c = svalue[i];
                if (inQuote)
                {
                    if (escapeNext)
                    {
                        escapeNext = false;
                    }
                    else
                    {
                        switch (c)
                        {
                            case HttpConstants.BackSlashChar:
                                escapeNext = true;
                                break;

                            case HttpConstants.DoubleQuoteChar:
                                inQuote = false;
                                break;
                        }
                    }
                }
                else
                {
                    switch (c)
                    {
                        case HttpConstants.DoubleQuoteChar:
                            inQuote = true;
                            break;
                        case HttpConstants.SemicolonChar:
                            values.Add(svalue.SubSequence(start, i));
                            start = i + 1;
                            break;
                    }
                }
            }
            values.Add(svalue.SubSequence(start));
            return values.ToArray();
        }
    }
}

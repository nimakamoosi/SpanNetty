﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Buffers
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using DotNetty.Common.Internal;
    using DotNetty.Common.Utilities;

    sealed class PoolChunkList<T> : IPoolChunkListMetric
    {
        private readonly PoolArena<T> _arena;
        private readonly PoolChunkList<T> _nextList;
        private readonly int _minUsage;
        private readonly int _maxUsage;
        private readonly int _maxCapacity;
        private PoolChunk<T> _head;

        // This is only update once when create the linked like list of PoolChunkList in PoolArena constructor.
        PoolChunkList<T> _prevList;

        // TODO: Test if adding padding helps under contention
        //private long pad0, pad1, pad2, pad3, pad4, pad5, pad6, pad7;

        public PoolChunkList(PoolArena<T> arena, PoolChunkList<T> nextList, int minUsage, int maxUsage, int chunkSize)
        {
            Debug.Assert(minUsage <= maxUsage);
            _arena = arena;
            _nextList = nextList;
            _minUsage = minUsage;
            _maxUsage = maxUsage;
            _maxCapacity = CalculateMaxCapacity(minUsage, chunkSize);
        }

        /// Calculates the maximum capacity of a buffer that will ever be possible to allocate out of the {@link PoolChunk}s
        /// that belong to the {@link PoolChunkList} with the given {@code minUsage} and {@code maxUsage} settings.
        static int CalculateMaxCapacity(int minUsage, int chunkSize)
        {
            minUsage = MinUsage0(minUsage);

            if (minUsage == 100)
            {
                // If the minUsage is 100 we can not allocate anything out of this list.
                return 0;
            }

            // Calculate the maximum amount of bytes that can be allocated from a PoolChunk in this PoolChunkList.
            //
            // As an example:
            // - If a PoolChunkList has minUsage == 25 we are allowed to allocate at most 75% of the chunkSize because
            //   this is the maximum amount available in any PoolChunk in this PoolChunkList.
            return (int)(chunkSize * (100L - minUsage) / 100L);
        }

        internal void PrevList(PoolChunkList<T> list)
        {
            Debug.Assert(_prevList is null);
            _prevList = list;
        }

        internal bool Allocate(PooledByteBuffer<T> buf, int reqCapacity, int normCapacity)
        {
            if (_head is null || normCapacity > _maxCapacity)
            {
                // Either this PoolChunkList is empty or the requested capacity is larger then the capacity which can
                // be handled by the PoolChunks that are contained in this PoolChunkList.
                return false;
            }

            for (PoolChunk<T> cur = _head;;)
            {
                long handle = cur.Allocate(normCapacity);
                if (handle < 0)
                {
                    cur = cur.Next;
                    if (cur is null)
                    {
                        return false;
                    }
                }
                else
                {
                    cur.InitBuf(buf, handle, reqCapacity);
                    if (cur.Usage >= _maxUsage)
                    {
                        Remove(cur);
                        _nextList.Add(cur);
                    }
                    return true;
                }
            }
        }

        internal bool Free(PoolChunk<T> chunk, long handle)
        {
            chunk.Free(handle);
            if (chunk.Usage < _minUsage)
            {
                Remove(chunk);
                // Move the PoolChunk down the PoolChunkList linked-list.
                return Move0(chunk);
            }
            return true;
        }

        bool Move(PoolChunk<T> chunk)
        {
            Debug.Assert(chunk.Usage < _maxUsage);

            if (chunk.Usage < _minUsage)
            {
                // Move the PoolChunk down the PoolChunkList linked-list.
                return Move0(chunk);
            }

            // PoolChunk fits into this PoolChunkList, adding it here.
            Add0(chunk);
            return true;
        }

        /// Moves the {@link PoolChunk} down the {@link PoolChunkList} linked-list so it will end up in the right
        /// {@link PoolChunkList} that has the correct minUsage / maxUsage in respect to {@link PoolChunk#usage()}.
        bool Move0(PoolChunk<T> chunk)
        {
            if (_prevList is null)
            {
                // There is no previous PoolChunkList so return false which result in having the PoolChunk destroyed and
                // all memory associated with the PoolChunk will be released.
                Debug.Assert(chunk.Usage == 0);
                return false;
            }
            return _prevList.Move(chunk);
        }

        internal void Add(PoolChunk<T> chunk)
        {
            if (chunk.Usage >= _maxUsage)
            {
                _nextList.Add(chunk);
                return;
            }
            Add0(chunk);
        }

        /// Adds the {@link PoolChunk} to this {@link PoolChunkList}.
        void Add0(PoolChunk<T> chunk)
        {
            chunk.Parent = this;
            if (_head is null)
            {
                _head = chunk;
                chunk.Prev = null;
                chunk.Next = null;
            }
            else
            {
                chunk.Prev = null;
                chunk.Next = _head;
                _head.Prev = chunk;
                _head = chunk;
            }
        }

        void Remove(PoolChunk<T> cur)
        {
            if (cur == _head)
            {
                _head = cur.Next;
                if (_head is object)
                {
                    _head.Prev = null;
                }
            }
            else
            {
                PoolChunk<T> next = cur.Next;
                cur.Prev.Next = next;
                if (next is object)
                {
                    next.Prev = cur.Prev;
                }
            }
        }

        public int MinUsage => MinUsage0(_minUsage);

        public int MaxUsage => Math.Min(_maxUsage, 100);

        static int MinUsage0(int value) => Math.Max(1, value);

        public IEnumerator<IPoolChunkMetric> GetEnumerator() => 
            _head is null ? Enumerable.Empty<IPoolChunkMetric>().GetEnumerator() : GetEnumeratorInternal();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        IEnumerator<IPoolChunkMetric> GetEnumeratorInternal()
        {
            lock (_arena)
            {
                for (PoolChunk<T> cur = _head; cur is object;)
                {
                    yield return cur;
                    cur = cur.Next;
                }
            }
        }

        public override string ToString()
        {
            var buf = StringBuilderManager.Allocate();
            lock (_arena)
            {
                if (_head is null)
                {
                    StringBuilderManager.Free(buf);
                    return "none";
                }

                for (PoolChunk<T> cur = _head; ;)
                {
                    _ = buf.Append(cur);
                    cur = cur.Next;
                    if (cur is null)
                    {
                        break;
                    }
                    _ = buf.Append(StringUtil.Newline);
                }
            }

            return StringBuilderManager.ReturnAndFree(buf);
        }

        internal void Destroy(PoolArena<T> poolArena)
        {
            PoolChunk<T> chunk = _head;
            while (chunk is object)
            {
                poolArena.DestroyChunk(chunk);
                chunk = chunk.Next;
            }

            _head = null;
        }
    }
}
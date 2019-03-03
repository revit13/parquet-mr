/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.parquet.hadoop;

import static org.apache.parquet.column.statistics.Statistics.getStatsBasedOnType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.parquet.bytes.BytesInput;
import org.apache.parquet.bytes.ConcatenatingByteArrayCollector;
import org.apache.parquet.column.ColumnDescriptor;
import org.apache.parquet.column.Encoding;
import org.apache.parquet.column.page.DictionaryPage;
import org.apache.parquet.column.page.PageWriteStore;
import org.apache.parquet.column.page.PageWriter;
import org.apache.parquet.column.statistics.Statistics;
import org.apache.parquet.crypto.AesEncryptor;
import org.apache.parquet.crypto.InternalColumnEncryptionSetup;
import org.apache.parquet.crypto.InternalFileEncryptor;
import org.apache.parquet.format.BlockCipher;
import org.apache.parquet.format.converter.ParquetMetadataConverter;
import org.apache.parquet.hadoop.CodecFactory.BytesCompressor;
import org.apache.parquet.hadoop.metadata.ColumnPath;
import org.apache.parquet.io.ParquetEncodingException;
import org.apache.parquet.schema.MessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ColumnChunkPageWriteStore implements PageWriteStore {
  private static final Logger LOG = LoggerFactory.getLogger(ColumnChunkPageWriteStore.class);

  private static ParquetMetadataConverter parquetMetadataConverter = new ParquetMetadataConverter();

  private static final class ColumnChunkPageWriter implements PageWriter {

    private final ColumnDescriptor path;
    private final BytesCompressor compressor;

    private final ByteArrayOutputStream tempOutputStream = new ByteArrayOutputStream();
    private final ConcatenatingByteArrayCollector buf;
    private DictionaryPage dictionaryPage;

    private long uncompressedLength;
    private long compressedLength;
    private long totalValueCount;
    private int pageCount;

    // repetition and definition level encodings are used only for v1 pages and don't change
    private Set<Encoding> rlEncodings = new HashSet<Encoding>();
    private Set<Encoding> dlEncodings = new HashSet<Encoding>();
    private List<Encoding> dataEncodings = new ArrayList<Encoding>();

    private Statistics totalStatistics;
    
    private final BlockCipher.Encryptor headerBlockEncryptor;
    private final BlockCipher.Encryptor pageBlockEncryptor;
    private final short rowGroupOrdinal;
    private final short columnOrdinal;
    private short pageOrdinal;  // TODO replace with pageCount?
    private byte[] dataPageAAD;
    private byte[] dataPageHeaderAAD;
    private final byte[] fileAAD;

    private ColumnChunkPageWriter(ColumnDescriptor path, BytesCompressor compressor,
        BlockCipher.Encryptor headerBlockEncryptor,  BlockCipher.Encryptor pageBlockEncryptor,
        byte[] fileAAD,
        short rowGroupOrdinal,
        short columnOrdinal) {
      this.path = path;
      this.headerBlockEncryptor = headerBlockEncryptor;
      this.pageBlockEncryptor = pageBlockEncryptor;
      this.compressor = compressor;
      this.buf = new ConcatenatingByteArrayCollector();
      this.totalStatistics = getStatsBasedOnType(this.path.getType());
      this.fileAAD = fileAAD;
      this.rowGroupOrdinal = rowGroupOrdinal;
      this.columnOrdinal = columnOrdinal;
      this.pageOrdinal = -1;
      if (null != headerBlockEncryptor) {
        dataPageHeaderAAD = AesEncryptor.createModuleAAD(fileAAD, AesEncryptor.DataPageHeader, 
            rowGroupOrdinal, columnOrdinal, (short) -1);
      }
      if (null != pageBlockEncryptor) {
        dataPageAAD = AesEncryptor.createModuleAAD(fileAAD, AesEncryptor.DataPage, 
            rowGroupOrdinal, columnOrdinal, (short) -1);
      }
    }

    @Override
    public void writePage(BytesInput bytes,
                          int valueCount,
                          Statistics statistics,
                          Encoding rlEncoding,
                          Encoding dlEncoding,
                          Encoding valuesEncoding) throws IOException {
      if (Short.MAX_VALUE == pageOrdinal) {
        throw new RuntimeException("Number of pages exceeds maximum: " + Short.MAX_VALUE);
      }
      pageOrdinal++;
      long uncompressedSize = bytes.size();
      if (uncompressedSize > Integer.MAX_VALUE) {
        throw new ParquetEncodingException(
            "Cannot write page larger than Integer.MAX_VALUE bytes: " +
            uncompressedSize);
      }
      BytesInput compressedBytes = compressor.compress(bytes);
      if (null != pageBlockEncryptor) {
        AesEncryptor.quickUpdatePageAAD(dataPageAAD, pageOrdinal);
        compressedBytes = BytesInput.from(pageBlockEncryptor.encrypt(compressedBytes.toByteArray(), dataPageAAD));
      }
      long compressedSize = compressedBytes.size();
      if (compressedSize > Integer.MAX_VALUE) {
        throw new ParquetEncodingException(
            "Cannot write compressed page larger than Integer.MAX_VALUE bytes: "
            + compressedSize);
      }
      tempOutputStream.reset();
      if (null != headerBlockEncryptor) {
        AesEncryptor.quickUpdatePageAAD(dataPageHeaderAAD, pageOrdinal);
      }
      parquetMetadataConverter.writeDataPageHeader(
          (int)uncompressedSize,
          (int)compressedSize,
          valueCount,
          statistics,
          rlEncoding,
          dlEncoding,
          valuesEncoding,
          tempOutputStream,
          headerBlockEncryptor,
          dataPageHeaderAAD);
      this.uncompressedLength += uncompressedSize;
      this.compressedLength += compressedSize;
      this.totalValueCount += valueCount;
      this.pageCount += 1;
      this.totalStatistics.mergeStatistics(statistics);
      // by concatenating before collecting instead of collecting twice,
      // we only allocate one buffer to copy into instead of multiple.
      buf.collect(BytesInput.concat(BytesInput.from(tempOutputStream), compressedBytes));
      rlEncodings.add(rlEncoding);
      dlEncodings.add(dlEncoding);
      dataEncodings.add(valuesEncoding);
    }

    @Override
    public void writePageV2(
        int rowCount, int nullCount, int valueCount,
        BytesInput repetitionLevels, BytesInput definitionLevels,
        Encoding dataEncoding, BytesInput data,
        Statistics<?> statistics) throws IOException {
      if (Short.MAX_VALUE == pageOrdinal) {
        throw new RuntimeException("Number of pages exceeds maximum: " + Short.MAX_VALUE);
      }
      pageOrdinal++;
      int rlByteLength = toIntWithCheck(repetitionLevels.size());
      int dlByteLength = toIntWithCheck(definitionLevels.size());
      int uncompressedSize = toIntWithCheck(
          data.size() + repetitionLevels.size() + definitionLevels.size()
      );
      // TODO: decide if we compress
      BytesInput compressedData = compressor.compress(data);
      if (null != pageBlockEncryptor) {
        AesEncryptor.quickUpdatePageAAD(dataPageAAD, pageOrdinal);
        compressedData = BytesInput.from(pageBlockEncryptor.encrypt(compressedData.toByteArray(), dataPageAAD));
      }
      int compressedSize = toIntWithCheck(
          compressedData.size() + repetitionLevels.size() + definitionLevels.size()
      );
      tempOutputStream.reset();
      if (null != headerBlockEncryptor) {
        AesEncryptor.quickUpdatePageAAD(dataPageHeaderAAD, pageOrdinal);
      }
      parquetMetadataConverter.writeDataPageV2Header(
          uncompressedSize, compressedSize,
          valueCount, nullCount, rowCount,
          statistics,
          dataEncoding,
          rlByteLength,
          dlByteLength,
          tempOutputStream,
          headerBlockEncryptor,
          dataPageHeaderAAD
          );
      this.uncompressedLength += uncompressedSize;
      this.compressedLength += compressedSize;
      this.totalValueCount += valueCount;
      this.pageCount += 1;
      this.totalStatistics.mergeStatistics(statistics);

      // by concatenating before collecting instead of collecting twice,
      // we only allocate one buffer to copy into instead of multiple.
      buf.collect(
          BytesInput.concat(
            BytesInput.from(tempOutputStream),
            repetitionLevels,
            definitionLevels,
            compressedData)
      );
      dataEncodings.add(dataEncoding);
    }

    private int toIntWithCheck(long size) {
      if (size > Integer.MAX_VALUE) {
        throw new ParquetEncodingException(
            "Cannot write page larger than " + Integer.MAX_VALUE + " bytes: " +
            size);
      }
      return (int)size;
    }

    @Override
    public long getMemSize() {
      return buf.size();
    }

    public void writeToFileWriter(ParquetFileWriter writer) throws IOException {
      writer.startColumn(path, totalValueCount, compressor.getCodecName());
      if (dictionaryPage != null) {
        byte[] dictonaryPageHeaderAAD = null;
        if (null != headerBlockEncryptor) {
          dictonaryPageHeaderAAD = AesEncryptor.createModuleAAD(fileAAD, AesEncryptor.DictionaryPageHeader, 
              rowGroupOrdinal, columnOrdinal, (short) -1);
        }
        writer.writeDictionaryPage(dictionaryPage, headerBlockEncryptor, dictonaryPageHeaderAAD);
        // tracking the dictionary encoding is handled in writeDictionaryPage
      }
      writer.writeDataPages(buf, uncompressedLength, compressedLength, totalStatistics,
          rlEncodings, dlEncodings, dataEncodings);
      writer.endColumn();
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            String.format(
                "written %,dB for %s: %,d values, %,dB raw, %,dB comp, %d pages, encodings: %s",
                buf.size(), path, totalValueCount, uncompressedLength, compressedLength, pageCount, new HashSet<Encoding>(dataEncodings))
                + (dictionaryPage != null ? String.format(
                ", dic { %,d entries, %,dB raw, %,dB comp}",
                dictionaryPage.getDictionarySize(), dictionaryPage.getUncompressedSize(), dictionaryPage.getDictionarySize())
                : ""));
      }
      rlEncodings.clear();
      dlEncodings.clear();
      dataEncodings.clear();
      pageCount = 0;
    }

    @Override
    public long allocatedSize() {
      return buf.size();
    }

    @Override
    public void writeDictionaryPage(DictionaryPage dictionaryPage) throws IOException {
      if (this.dictionaryPage != null) {
        throw new ParquetEncodingException("Only one dictionary page is allowed");
      }
      BytesInput dictionaryBytes = dictionaryPage.getBytes();
      int uncompressedSize = (int)dictionaryBytes.size();
      BytesInput compressedBytes = compressor.compress(dictionaryBytes);
      if (null != pageBlockEncryptor) {
        byte[] dictonaryPageAAD = AesEncryptor.createModuleAAD(fileAAD, AesEncryptor.DictionaryPage, rowGroupOrdinal, columnOrdinal, (short) -1);
        compressedBytes = BytesInput.from(pageBlockEncryptor.encrypt(compressedBytes.toByteArray(), dictonaryPageAAD));
      }
      this.dictionaryPage = new DictionaryPage(BytesInput.copy(compressedBytes), uncompressedSize, dictionaryPage.getDictionarySize(), dictionaryPage.getEncoding());
    }

    @Override
    public String memUsageString(String prefix) {
      return buf.memUsageString(prefix + " ColumnChunkPageWriter");
    }
  }

  private final Map<ColumnDescriptor, ColumnChunkPageWriter> writers = new HashMap<ColumnDescriptor, ColumnChunkPageWriter>();
  private final MessageType schema;

  public ColumnChunkPageWriteStore(BytesCompressor compressor, MessageType schema) {
    this.schema = schema;
    for (ColumnDescriptor path : schema.getColumns()) {
      writers.put(path,  new ColumnChunkPageWriter(path, compressor, (BlockCipher.Encryptor) null, (BlockCipher.Encryptor) null, (byte[]) null, (short) -1, (short) -1));
    }
  }
  
  public ColumnChunkPageWriteStore(BytesCompressor compressor, MessageType schema, InternalFileEncryptor fileEncryptor, short rowGroupOrdinal) throws IOException {
    this.schema = schema;
    short columnOrdinal = -1;
    byte[] fileAAD = (null == fileEncryptor? null : fileEncryptor.getFileAAD());
    for (ColumnDescriptor path : schema.getColumns()) {
      columnOrdinal++;
      BlockCipher.Encryptor headerBlockEncryptor = null;
      BlockCipher.Encryptor pageBlockEncryptor = null;
      if (null != fileEncryptor) {
        InternalColumnEncryptionSetup columnSetup = null;
        columnSetup = fileEncryptor.getColumnSetup(ColumnPath.get(path.getPath()), true, columnOrdinal);
        if (columnSetup.isEncrypted()) {
          headerBlockEncryptor = columnSetup.getMetaDataEncryptor();
          pageBlockEncryptor = columnSetup.getDataEncryptor();
        }
      }
      writers.put(path,  new ColumnChunkPageWriter(path, compressor, headerBlockEncryptor, pageBlockEncryptor, fileAAD, rowGroupOrdinal, columnOrdinal));
    }
  }

  @Override
  public PageWriter getPageWriter(ColumnDescriptor path) {
    return writers.get(path);
  }

  public void flushToFileWriter(ParquetFileWriter writer) throws IOException {
    for (ColumnDescriptor path : schema.getColumns()) {
      ColumnChunkPageWriter pageWriter = writers.get(path);
      pageWriter.writeToFileWriter(writer);
    }
  }

}

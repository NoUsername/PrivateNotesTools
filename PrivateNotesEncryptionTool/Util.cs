/**
 * PrivateNotes is an encryption scheme and notes encryption tool.
 * Copyright (C) 2010, 2011 Paul Klingelhuber
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 **/
#define RANDOM_PADDING

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace Tomboy.PrivateNotes
{
  public class Util
  {
#if RANDOM_PADDING
    private static Random random = new Random();
#endif

    public static void AssureFileExists(String _path)
    {
      if (!File.Exists(_path))
        File.Create(_path).Close();
    }

    public static void DelelteFilesInDirectory(String _path)
    {
      DirectoryInfo info = new DirectoryInfo(_path);
      foreach (FileInfo file in info.GetFiles())
      {
        file.Delete();
      }
    }

    public static DateTime ConvertFromUnixTimestamp(long timestamp)
    {
      DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
      return origin.AddSeconds(timestamp);
    }


    public static long ConvertToUnixTimestamp(DateTime date)
    {
      DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
      TimeSpan diff = date - origin;
      return (long)Math.Floor(diff.TotalSeconds);
    }

    public static byte[] GetBytes(String _s)
    {
      return Encoding.UTF8.GetBytes(_s);
    }

    public static String FromBytes(byte[] _data)
    {
      return Encoding.UTF8.GetString(_data);
    }

    public static bool ArraysAreEqual(byte[] _array1, byte[] _array2)
    {
      if (_array1 == null || _array2 == null)
        return false;
      if (_array1 == _array2)
        return true;
      if (_array1.Length != _array2.Length)
        return false;

      for (int i = 0; i < _array1.Length; i++)
        if (_array1[i] != _array2[i])
          return false;

      return true;
    }

    public static byte[] padData(byte[] _data, int _multipleOf)
    {
      int tooMuch = _data.Length % _multipleOf;
      int padBytes = _multipleOf - tooMuch;
      byte[] newData = new byte[_data.Length + padBytes];
      System.Array.Copy(_data, newData, _data.Length);
#if RANDOM_PADDING
      // fill rest with random data
      byte[] randomPad = new byte[padBytes];
      random.NextBytes(randomPad);
      System.Array.Copy(randomPad, 0, newData, _data.Length, padBytes);
#endif
      return newData;
    }

    /// <summary>
    /// adds 4 byte length info at the beginning, supports max. length of the max value of int32
    /// </summary>
    /// <param name="_data"></param>
    /// <param name="_multipleOf"></param>
    /// <returns></returns>
    public static byte[] padWithLengthInfo(byte[] _data, int _multipleOf)
    {
      int tooMuch = (_data.Length + 4) % _multipleOf;
      int padBytes = _multipleOf - tooMuch;
      byte[] newData = new byte[_data.Length + padBytes + 4];
      if (_data.LongLength > Int32.MaxValue)
      {
        throw new InvalidOperationException("you can't use this much of data, because the length information only uses 4 bytes");
      }
      // get length info
      byte[] lengthInfo = System.BitConverter.GetBytes((int)_data.Length);
      // write length info
      System.Array.Copy(lengthInfo, 0, newData, 0, lengthInfo.Length);
      // write data
      System.Array.Copy(_data, 0, newData, 4, _data.Length);
#if RANDOM_PADDING
      // fill rest with random data
      byte[] randomPad = new byte[padBytes];
      random.NextBytes(randomPad);
      System.Array.Copy(randomPad, 0, newData, lengthInfo.Length + _data.Length, padBytes);
#endif
      return newData;
    }

    /// <summary>
    /// reads the first 4 bytes of an array, converts that to an int, and reads that many following bytes of
    /// the array and returns them
    /// </summary>
    /// <param name="_data"></param>
    /// <returns></returns>
    public static byte[] getDataFromPaddedWithLengthInfo(byte[] _data)
    {
      if (_data.Length < 4)
        throw new InvalidOperationException("the data must at least contain the length info");

      int lenghtInfo = BitConverter.ToInt32(_data, 0);
      if (_data.Length < 4 + lenghtInfo)
        throw new InvalidOperationException("length info invalid, array not long enough to hold that much data");

      byte[] realData = new byte[lenghtInfo];
      System.Array.Copy(_data, 4, realData, 0, lenghtInfo);
      return realData;
    }
  }

}

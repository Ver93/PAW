
import { useMemo } from "react";
import "./PacketDump.css";

const MAX_DUMP_BYTES = 2048;
const BYTES_PER_ROW = 16;

// Exempeldata används endast om packet.data saknas.
const EXAMPLE_DATA = [
  0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
  0x40, 0x06, 0x7c, 0x9c, 0xc0, 0xa8, 0x01, 0x64,

  0xc0, 0xa8, 0x01, 0x01, 0x00, 0x50, 0xc3, 0x21,
  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,

  0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x50, 0x43,
  0x41, 0x50, 0x4e, 0x47, 0x20, 0x41, 0x6e, 0x61,

  0x6c, 0x79, 0x7a, 0x65, 0x72, 0x00, 0xff, 0x10,
  0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
];

function byteToHex(byte) {
  return byte
    .toString(16)
    .padStart(2, "0")
    .toUpperCase();
}

function byteToAscii(byte) {
  return byte >= 32 && byte <= 126
    ? String.fromCharCode(byte)
    : ".";
}

function formatOffset(offset) {
  return offset.toString(16).padStart(8, "0").toUpperCase();
}

export default function PacketDump({ packet }) {
  const data = useMemo(() => {
    const packetData = packet?.data;

    if (
      Array.isArray(packetData) &&
      packetData.length > 0
    ) {
      return packetData.slice(0, MAX_DUMP_BYTES);
    }

    return EXAMPLE_DATA;
  }, [packet]);

  const rows = useMemo(() => {
    const result = [];

    for (
      let offset = 0;
      offset < data.length;
      offset += BYTES_PER_ROW
    ) {
      const bytes = data.slice(
        offset,
        offset + BYTES_PER_ROW
      );

      result.push({
        offset,
        bytes,
      });
    }

    return result;
  }, [data]);

  const actualByteCount = packet?.data?.length ?? 0;

  const showingExampleData =
    !Array.isArray(packet?.data) ||
    packet.data.length === 0;

  const isTruncated =
    !showingExampleData &&
    actualByteCount > MAX_DUMP_BYTES;

  return (
    <div className="packet-dump">
      <div className="dump-header">
        <div>
          <h3>Packet Bytes</h3>
          <span className="dump-subtitle">
            Offset · Hex · ASCII
          </span>
        </div>

        <span className="dump-count">
          {showingExampleData
            ? "EXAMPLE"
            : `${actualByteCount.toLocaleString()} BYTES`}
        </span>
      </div>

      <div className="dump-table-wrapper">
        <table className="dump-table">
          <thead>
            <tr>
              <th className="offset-column">
                Offset
              </th>

              {Array.from(
                { length: BYTES_PER_ROW },
                (_, index) => (
                  <th
                    key={index}
                    className="hex-column"
                  >
                    {index
                      .toString(16)
                      .padStart(2, "0")
                      .toUpperCase()}
                  </th>
                )
              )}

              <th className="ascii-column">
                ASCII
              </th>
            </tr>
          </thead>

          <tbody>
            {rows.map(({ offset, bytes }) => (
              <tr key={offset}>
                <td className="offset-cell">
                  {formatOffset(offset)}
                </td>

                {Array.from(
                  { length: BYTES_PER_ROW },
                  (_, index) => {
                    const byte = bytes[index];

                    return (
                      <td
                        key={index}
                        className={
                          byte === undefined
                            ? "hex-cell empty"
                            : "hex-cell"
                        }
                      >
                        {byte === undefined
                          ? ""
                          : byteToHex(byte)}
                      </td>
                    );
                  }
                )}

                <td className="ascii-cell">
                  {bytes.map((byte, index) => (
                    <span
                      key={index}
                      className={
                        byte >= 32 && byte <= 126
                          ? "ascii-printable"
                          : "ascii-nonprintable"
                      }
                    >
                      {byteToAscii(byte)}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {isTruncated && (
        <div className="dump-truncated">
          Visar första{" "}
          {MAX_DUMP_BYTES.toLocaleString()}{" "}
          av{" "}
          {actualByteCount.toLocaleString()}{" "}
          bytes
        </div>
      )}

      {showingExampleData && (
        <div className="dump-example">
          Exempeldata visas eftersom paketet saknar byte-data.
        </div>
      )}
    </div>
  );
}

import { useMemo, useState } from "react";
import {
  useNavigate,
  useSearchParams,
} from "react-router-dom";

import PageHeader from "./PageHeader";

import "./Flows.css";

export default function Flows({
  flows = [],
  filename,
}) {
  const navigate = useNavigate();

  const [searchParams, setSearchParams] =
    useSearchParams();

  const [filter, setFilter] = useState(
    searchParams.get("filter") || ""
  );

  const [sortKey, setSortKey] = useState("count");
  const [sortDirection, setSortDirection] =
    useState("desc");

  const sortFlows = (a, b) => {
    let aValue;
    let bValue;

    switch (sortKey) {
      case "source":
        aValue = `${a.src || ""}:${a.srcPort ?? ""}`;
        bValue = `${b.src || ""}:${b.srcPort ?? ""}`;
        break;

      case "destination":
        aValue = `${a.dst || ""}:${a.dstPort ?? ""}`;
        bValue = `${b.dst || ""}:${b.dstPort ?? ""}`;
        break;

      case "protocol":
        aValue = a.protocol || "";
        bValue = b.protocol || "";
        break;

      case "count":
      default:
        aValue = Number(a.count) || 0;
        bValue = Number(b.count) || 0;
        break;
    }

    if (
      typeof aValue === "number" &&
      typeof bValue === "number"
    ) {
      return sortDirection === "asc"
        ? aValue - bValue
        : bValue - aValue;
    }

    const comparison = String(aValue).localeCompare(
      String(bValue)
    );

    return sortDirection === "asc"
      ? comparison
      : -comparison;
  };

  const filteredFlows = useMemo(() => {
    const query = filter.trim().toLowerCase();

    if (!query) {
      return [...flows].sort((a, b) =>
        sortFlows(a, b)
      );
    }

    const expressions = query
      .split("&&")
      .map((part) => part.trim())
      .filter(Boolean);

    const result = flows.filter((flow) => {
      const searchableValues = [
        flow.id,
        flow.src,
        flow.srcPort,
        flow.dst,
        flow.dstPort,
        flow.protocol,
        flow.count,
      ]
        .filter(
          (value) =>
            value !== undefined &&
            value !== null
        )
        .map((value) =>
          String(value).toLowerCase()
        );

      return expressions.every((expression) =>
        searchableValues.some((value) =>
          value.includes(expression)
        )
      );
    });

    return [...result].sort((a, b) =>
      sortFlows(a, b)
    );
  }, [
    flows,
    filter,
    sortKey,
    sortDirection,
  ]);

  const handleSort = (key) => {
    if (sortKey === key) {
      setSortDirection((current) =>
        current === "asc" ? "desc" : "asc"
      );

      return;
    }

    setSortKey(key);
    setSortDirection("asc");
  };

  const sortIndicator = (key) => {
    if (sortKey !== key) {
      return "";
    }

    return sortDirection === "asc"
      ? " ↑"
      : " ↓";
  };

  const handleFilterChange = (event) => {
    const value = event.target.value;

    setFilter(value);

    const trimmed = value.trim();

    if (!trimmed) {
      setSearchParams({});
      return;
    }

    setSearchParams({
      filter: value,
    });
  };

  const clearFilter = () => {
    setFilter("");
    setSearchParams({});
  };

  return (
    <>
      <PageHeader
        title="Flows"
        subtitle="Network conversations detected in the capture."
        filename={filename}
      />

      <div className="flows-page">
        <div className="flows-filterbar">
          <label htmlFor="flow-filter">
            Display filter
          </label>

          <input
            id="flow-filter"
            type="text"
            value={filter}
            onChange={handleFilterChange}
            placeholder="ip, port, protocol..."
            spellCheck="false"
            autoComplete="off"
          />

          {filter && (
            <button
              className="filter-clear"
              onClick={clearFilter}
              type="button"
            >
              Clear
            </button>
          )}

          <span className="flows-visible-count">
            {filteredFlows.length} of {flows.length}
          </span>
        </div>

        <div className="flows-table-container">
          <table className="flows-table">
            <thead>
              <tr>
                <th className="column-number">
                  #
                </th>

                <th
                  onClick={() => handleSort("source")}
                  className="sortable"
                >
                  Source
                  {sortIndicator("source")}
                </th>

                <th
                  onClick={() =>
                    handleSort("destination")
                  }
                  className="sortable"
                >
                  Destination
                  {sortIndicator("destination")}
                </th>

                <th
                  onClick={() =>
                    handleSort("protocol")
                  }
                  className="sortable column-protocol"
                >
                  Protocol
                  {sortIndicator("protocol")}
                </th>

                <th
                  onClick={() => handleSort("count")}
                  className="sortable column-number-value"
                >
                  Packets
                  {sortIndicator("count")}
                </th>

                <th className="column-number-value">
                  Bytes
                </th>

                <th className="column-duration">
                  Duration
                </th>
              </tr>
            </thead>

            <tbody>
              {filteredFlows.length === 0 ? (
                <tr>
                  <td
                    colSpan="7"
                    className="flows-empty"
                  >
                    {flows.length === 0
                      ? "No flows found."
                      : "No flows match the current filter."}
                  </td>
                </tr>
              ) : (
                filteredFlows.map((flow, index) => (
                  <tr
                    key={flow.id}
                    className="flow-row"
                    onClick={() =>
                      navigate(
                        `/flow/${encodeURIComponent(
                          String(flow.id)
                        )}`
                      )
                    }
                  >
                    <td className="column-number">
                      {index + 1}
                    </td>

                    <td className="endpoint">
                      <span>
                        {flow.src || "—"}
                      </span>

                      <small>
                        :{flow.srcPort ?? "—"}
                      </small>
                    </td>

                    <td className="endpoint">
                      <span>
                        {flow.dst || "—"}
                      </span>

                      <small>
                        :{flow.dstPort ?? "—"}
                      </small>
                    </td>

                    <td className="protocol">
                      {flow.protocol || "IPv4"}
                    </td>

                    <td className="number">
                      {flow.count ?? 0}
                    </td>

                    <td className="number muted">
                      {flow.bytes
                        ? flow.bytes.toLocaleString()
                        : "—"}
                    </td>

                    <td className="duration muted">
                      {flow.duration
                        ? `${flow.duration}s`
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

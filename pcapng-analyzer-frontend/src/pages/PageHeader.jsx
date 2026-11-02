import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";

import "./PageHeader.css";

export default function PageHeader({
  title,
  subtitle,
  filename,
}) {
  const [darkMode, setDarkMode] = useState(() => {
    return localStorage.getItem("theme") !== "light";
  });

  useEffect(() => {
    document.documentElement.setAttribute(
      "data-theme",
      darkMode ? "dark" : "light"
    );

    localStorage.setItem(
      "theme",
      darkMode ? "dark" : "light"
    );
  }, [darkMode]);

  return (
    <header className="page-header">
      <div className="page-header-left">
        <div className="page-header-brand">
          <div className="page-header-eyebrow">
            NETWORK FORENSICS
          </div>

          <h1>{title}</h1>
        </div>

        <nav className="page-header-nav">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              `page-header-nav-link ${
                isActive ? "active" : ""
              }`
            }
          >
            Protocol Graph
          </NavLink>

          <NavLink
            to="/flows"
            className={({ isActive }) =>
              `page-header-nav-link ${
                isActive ? "active" : ""
              }`
            }
          >
            Flows
          </NavLink>

          {/* <NavLink
            to="/flow"
            end={false}
            className={({ isActive }) =>
              `page-header-nav-link ${
                isActive ? "active" : ""
              }`
            }
          >
            Flow Inspector
          </NavLink> */}
        </nav>
      </div>

      <div className="page-header-right">
        {filename && (
          <span className="page-header-filename">
            {filename}
          </span>
        )}

        <button
          type="button"
          className="page-header-theme"
          onClick={() =>
            setDarkMode((value) => !value)
          }
          title={
            darkMode
              ? "Light mode"
              : "Dark mode"
          }
          aria-label="Toggle theme"
        >
          {darkMode ? "☀" : "☾"}
        </button>
      </div>
    </header>
  );
}
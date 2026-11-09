import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import { Console } from "./components/fleet/Console";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Console />
  </StrictMode>
);

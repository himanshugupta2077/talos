import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import { ProjectProvider } from "./state/ProjectContext";
import { CommandLogProvider } from "./state/CommandLogContext";
import { StatusProvider } from "./state/StatusContext";

import Dashboard from "./pages/Dashboard";
import Projects from "./pages/Projects";
import Proxy from "./pages/Proxy";
import RolesModules from "./pages/RolesModules";
import Access from "./pages/Access";
import Auth from "./pages/Auth";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import Flows from "./pages/Flows";
import FlowDetail from "./pages/FlowDetail";
import Mutations from "./pages/Mutations";
import Scheduler from "./pages/Scheduler";
import Attack from "./pages/Attack";
import InputValidation from "./pages/InputValidation";
import ParameterDetail from "./pages/input-validation/ParameterDetail";
import IvEndpointIntel from "./pages/input-validation/IvEndpointIntel";
import IvHostIntel from "./pages/input-validation/IvHostIntel";
import SecretDetection from "./pages/SecretDetection";
import DetectionDetail from "./pages/secret-detection/DetectionDetail";
import DocumentDetail from "./pages/secret-detection/DocumentDetail";
import Findings from "./pages/Findings";
import FindingDetail from "./pages/FindingDetail";
import Console from "./pages/Console";
import TalosConfig from "./pages/TalosConfig";

export default function App() {
  return (
    <ProjectProvider>
      <CommandLogProvider>
        <StatusProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<Layout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/projects" element={<Projects />} />
              <Route path="/proxy" element={<Proxy />} />
              <Route path="/roles-modules" element={<RolesModules />} />
              <Route path="/access" element={<Access />} />
              <Route path="/auth" element={<Auth />} />
              <Route path="/endpoints" element={<Endpoints />} />
              <Route path="/endpoints/:endpointId" element={<EndpointDetail />} />
              <Route path="/flows" element={<Flows />} />
              <Route path="/flows/:flowId" element={<FlowDetail />} />
              <Route path="/mutations" element={<Mutations />} />
              <Route path="/scheduler" element={<Scheduler />} />
              <Route path="/attack" element={<Attack />} />
              <Route path="/input-validation" element={<InputValidation />} />
              <Route path="/input-validation/params/:paramUuid" element={<ParameterDetail />} />
              <Route path="/input-validation/endpoints/:endpointId" element={<IvEndpointIntel />} />
              <Route path="/input-validation/hosts/:host" element={<IvHostIntel />} />
              <Route path="/secret-detection" element={<SecretDetection />} />
              <Route path="/secret-detection/detections/:detectionId" element={<DetectionDetail />} />
              <Route path="/secret-detection/documents/:documentId" element={<DocumentDetail />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:findingId" element={<FindingDetail />} />
              <Route path="/console" element={<Console />} />
              <Route path="/talos-config" element={<TalosConfig />} />
            </Route>
          </Routes>
        </BrowserRouter>
        </StatusProvider>
      </CommandLogProvider>
    </ProjectProvider>
  );
}

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
import UnauthModule from "./pages/attack/modules/UnauthModule";
import BacModule from "./pages/attack/modules/BacModule";
import AuthSessionModule from "./pages/attack/modules/AuthSessionModule";
import IntruderModule from "./pages/attack/modules/IntruderModule";
import CorsModule from "./pages/attack/modules/CorsModule";
import SqliModule from "./pages/attack/modules/SqliModule";
import PathTraversalModule from "./pages/attack/modules/PathTraversalModule";
import SsrfModule from "./pages/attack/modules/SsrfModule";
import OpenRedirectModule from "./pages/attack/modules/OpenRedirectModule";
import HostHeaderModule from "./pages/attack/modules/HostHeaderModule";
import SmuggleModule from "./pages/attack/modules/SmuggleModule";
import LegacySecretRedirect from "./pages/attack/LegacySecretRedirect";
import LegacyIvRedirect from "./pages/attack/LegacyIvRedirect";
import LegacyAttackRedirect from "./pages/attack/LegacyAttackRedirect";
import InputValidation from "./pages/InputValidation";
import ParameterDetail from "./pages/input-validation/ParameterDetail";
import IvEndpointIntel from "./pages/input-validation/IvEndpointIntel";
import IvHostIntel from "./pages/input-validation/IvHostIntel";
import SecretDetection from "./pages/SecretDetection";
import DetectionDetail from "./pages/secret-detection/DetectionDetail";
import DocumentDetail from "./pages/secret-detection/DocumentDetail";
import ErrorIntelligence from "./pages/ErrorIntelligence";
import ErrorClusterDetail from "./pages/error-intelligence/ErrorClusterDetail";
import UrlSinkDiscovery from "./pages/UrlSinkDiscovery";
import Findings from "./pages/Findings";
import FindingDetail from "./pages/FindingDetail";
import Console from "./pages/Console";
import TalosConfig from "./pages/TalosConfig";
import Repeater from "./pages/Repeater";

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
              <Route path="/repeater" element={<Repeater />} />
              <Route path="/mutations" element={<Mutations />} />
              <Route path="/scheduler" element={<Scheduler />} />

              {/* Canonical Testing hub + modules */}
              <Route path="/testing" element={<Attack />} />
              <Route path="/testing/unauth" element={<UnauthModule />} />
              <Route path="/testing/bac" element={<BacModule />} />
              <Route path="/testing/auth-session" element={<AuthSessionModule />} />
              <Route path="/testing/intruder" element={<IntruderModule />} />
              <Route path="/testing/cors" element={<CorsModule />} />
              <Route path="/testing/sqli" element={<SqliModule />} />
              <Route path="/testing/path-traversal" element={<PathTraversalModule />} />
              <Route path="/testing/ssrf" element={<SsrfModule />} />
              <Route path="/testing/open-redirect" element={<OpenRedirectModule />} />
              <Route path="/testing/host-header" element={<HostHeaderModule />} />
              <Route path="/testing/smuggle" element={<SmuggleModule />} />
              <Route path="/testing/secrets" element={<SecretDetection />} />
              <Route
                path="/testing/secrets/detections/:detectionId"
                element={<DetectionDetail />}
              />
              <Route
                path="/testing/secrets/documents/:documentId"
                element={<DocumentDetail />}
              />
              <Route path="/testing/errors" element={<ErrorIntelligence />} />
              <Route
                path="/testing/errors/:errorId"
                element={<ErrorClusterDetail />}
              />
              <Route path="/testing/url-sinks" element={<UrlSinkDiscovery />} />
              <Route path="/testing/input-validation" element={<InputValidation />} />
              <Route
                path="/testing/input-validation/params/:paramUuid"
                element={<ParameterDetail />}
              />
              <Route
                path="/testing/input-validation/endpoints/:endpointId"
                element={<IvEndpointIntel />}
              />
              <Route
                path="/testing/input-validation/hosts/:host"
                element={<IvHostIntel />}
              />

              {/* Legacy /attack/* → /testing/* (preserve path, search, hash) */}
              <Route path="/attack/*" element={<LegacyAttackRedirect />} />
              <Route path="/attack" element={<LegacyAttackRedirect />} />
              {/* Older bookmarks → nested under Testing */}
              <Route path="/secret-detection/*" element={<LegacySecretRedirect />} />
              <Route path="/secret-detection" element={<LegacySecretRedirect />} />
              <Route path="/input-validation/*" element={<LegacyIvRedirect />} />
              <Route path="/input-validation" element={<LegacyIvRedirect />} />

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

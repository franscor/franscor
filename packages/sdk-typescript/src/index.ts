/**
 * FRANSCOR — secure interoperability layer for AI agents.
 *
 *   import franscor from 'franscor';
 *   franscor.capability('text.upper', ({ text }) => ({ text: text.toUpperCase() }), { risk: 'R0' });
 *   const agent = await franscor.connect({ name: 'writer' });
 *   console.log(agent.status, agent.identity.agentId, agent.capabilities);
 */
import { capability } from './capabilities.js';
import { Agent, connect } from './client.js';
import { detect } from './detect.js';
import { FSPError, TaskError } from './errors.js';
import { Identity } from './identity.js';

export { builtinAdapters, functionAdapter, langchainAdapter, type Adapter, type AdapterContext, type AdapterReport } from './adapters.js';
export { canonicalHash, canonicalJson, CanonicalError } from './canonical.js';
export { capability, defineCapability, type Capability, type CapabilityOptions, type Handler, type Risk, type TaskContext } from './capabilities.js';
export { Agent, connect, DEFAULT_HUB, type AgentCard, type AgentStatus, type ApprovalRequest, type ConnectOptions, type DelegateOptions, type Visibility } from './client.js';
export { detect, type Detection } from './detect.js';
export { FSP_VERSION, seal, verifyEnvelope, type Envelope } from './envelope.js';
export { Codes, FSPError, TaskError, type TaskStatus } from './errors.js';
export { EvidenceLog, readLog, verifyChain, verifyRecord, type EvidenceRecord } from './evidence.js';
export { agentIdFromPem, Identity, kidFromPem } from './identity.js';
export { AgentPolicy } from './policy.js';

const franscor = { connect, capability, detect, Agent, Identity, FSPError, TaskError };
export default franscor;
export { makeRevocation, makeRotation, verifyRevocation, verifyRotation, type RevocationStatement, type RotationStatement } from './statements.js';
export { importMcpTools, McpToolError, type ImportMcpOptions, type McpClientLike } from './mcp.js';
export { AuditError, EMPTY_ROOT, leafHash, merkleRoot, nodeHash, verifyBundle, verifyCheckpoint, verifyConsistency, verifyCosignature, verifyInclusion, type AuditBundle, type AuditCheckpoint, type AuditCosignature, type BundleReport, type VerifyBundleOptions } from './blackbox.js';
export { issuePermit, permitMatches, PERMIT_TTL_MS, requestTerms, verifyPermit, type Permit, type VerifyPermitOptions } from './permit.js';
export { crlRevokes, DEFAULT_TTL_MS, issuePassport, makeCrl, verifyCrl, verifyPassport, type CrlEntry, type Passport, type PassportCrl, type VerifyPassportOptions } from './passport.js';

import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  FileJson,
  GitPullRequest,
  Play,
  RefreshCw,
  RotateCw,
  Search,
  ShieldCheck
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { API_BASE, getReport, getStatus, retryJob, startScan } from './api.js';

const emptyForm = {
  github_repository: '',
  branch: '',
  base_branch: '',
  create_pr: false,
  full_scan: true,
  max_retry_count: 2
};

function App() {
  const [form, setForm] = useState(emptyForm);
  const [jobId, setJobId] = useState('');
  const [status, setStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [activeTab, setActiveTab] = useState('findings');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const running = ['queued', 'running', 'retrying'].includes(status?.status);
  const findings = report?.vulnerability_report?.vulnerabilities || [];
  const fixes = report?.fix_report?.fixes || [];
  const validation = report?.validation_report;

  useEffect(() => {
    if (!jobId) return undefined;
    let disposed = false;
    async function refresh() {
      try {
        const nextStatus = await getStatus(jobId);
        if (disposed) return;
        setStatus(nextStatus);
        const nextReport = await getReport(jobId);
        if (!disposed) setReport(nextReport);
      } catch (err) {
        if (!disposed) setError(err.message);
      }
    }
    refresh();
    const interval = setInterval(refresh, running ? 2500 : 8000);
    return () => {
      disposed = true;
      clearInterval(interval);
    };
  }, [jobId, running]);

  const severityCounts = useMemo(() => {
    return findings.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, {});
  }, [findings]);

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const payload = Object.fromEntries(
        Object.entries(form).filter(([, value]) => value !== '' && value !== null)
      );
      if (!payload.github_repository) {
        throw new Error('Provide a GitHub repository in owner/repo form.');
      }
      const response = await startScan(payload);
      setJobId(response.id);
      setStatus({ id: response.id, status: response.status, trace: [] });
      setReport(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function retry() {
    if (!jobId) return;
    setLoading(true);
    setError('');
    try {
      const response = await retryJob(jobId);
      setStatus(response);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Vuln-Swarm</p>
          <h1>Multi-agent security automation</h1>
        </div>
        <div className="api-pill">
          <Activity size={16} />
          <span>{API_BASE}</span>
        </div>
      </header>

      <section className="workspace">
        <form className="scan-panel" onSubmit={submit}>
          <div className="panel-heading">
            <Search size={18} />
            <h2>GitHub Target</h2>
          </div>
          <label>
            GitHub repository
            <input
              value={form.github_repository}
              placeholder="acme/app"
              onChange={(event) => setForm({ ...form, github_repository: event.target.value })}
            />
          </label>
          <div className="field-grid">
            <label>
              Branch
              <input
                value={form.branch}
                placeholder="main"
                onChange={(event) => setForm({ ...form, branch: event.target.value })}
              />
            </label>
            <label>
              Max retries
              <input
                type="number"
                min="0"
                max="10"
                value={form.max_retry_count}
                onChange={(event) =>
                  setForm({ ...form, max_retry_count: Number(event.target.value) })
                }
              />
            </label>
          </div>
          <label>
            Base branch
            <input
              value={form.base_branch}
              placeholder="main"
              onChange={(event) => setForm({ ...form, base_branch: event.target.value })}
            />
          </label>
          <div className="toggles">
            <label className="toggle">
              <input
                type="checkbox"
                checked={form.full_scan}
                onChange={(event) => setForm({ ...form, full_scan: event.target.checked })}
              />
              Full scan
            </label>
            <label className="toggle">
              <input
                type="checkbox"
                checked={form.create_pr}
                onChange={(event) => setForm({ ...form, create_pr: event.target.checked })}
              />
              Create PR
            </label>
          </div>
          <button className="primary" type="submit" disabled={loading}>
            {loading ? <RefreshCw size={18} className="spin" /> : <Play size={18} />}
            <span>Start Pipeline</span>
          </button>
          {error ? (
            <div className="error-line">
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
          ) : null}
        </form>

        <section className="run-panel">
          <div className="status-strip">
            <Metric icon={<ShieldCheck size={18} />} label="Status" value={status?.status || 'idle'} />
            <Metric icon={<AlertTriangle size={18} />} label="Findings" value={findings.length} />
            <Metric icon={<CheckCircle2 size={18} />} label="Validation" value={validation?.validation_status || 'pending'} />
            <Metric icon={<GitPullRequest size={18} />} label="PR" value={validation?.pr_url ? 'created' : 'none'} />
          </div>

          <div className="severity-row">
            {['critical', 'high', 'medium', 'low', 'info'].map((severity) => (
              <span key={severity} className={`severity ${severity}`}>
                {severity}: {severityCounts[severity] || 0}
              </span>
            ))}
          </div>

          <div className="tabs">
            <button className={activeTab === 'findings' ? 'active' : ''} onClick={() => setActiveTab('findings')}>
              Findings
            </button>
            <button className={activeTab === 'fixes' ? 'active' : ''} onClick={() => setActiveTab('fixes')}>
              Fixes
            </button>
            <button className={activeTab === 'validation' ? 'active' : ''} onClick={() => setActiveTab('validation')}>
              Validation
            </button>
            <button className={activeTab === 'trace' ? 'active' : ''} onClick={() => setActiveTab('trace')}>
              Trace
            </button>
            <button className={activeTab === 'json' ? 'active' : ''} onClick={() => setActiveTab('json')}>
              <FileJson size={15} />
              JSON
            </button>
          </div>

          <div className="tab-body">
            {activeTab === 'findings' && <Findings findings={findings} />}
            {activeTab === 'fixes' && <Fixes fixes={fixes} />}
            {activeTab === 'validation' && <Validation validation={validation} onRetry={retry} loading={loading} />}
            {activeTab === 'trace' && <Trace trace={status?.trace || report?.trace || []} />}
            {activeTab === 'json' && <pre className="json">{JSON.stringify(report || status || {}, null, 2)}</pre>}
          </div>
        </section>
      </section>
    </main>
  );
}

function Metric({ icon, label, value }) {
  return (
    <div className="metric">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Findings({ findings }) {
  if (!findings.length) return <Empty text="No findings loaded yet." />;
  return (
    <div className="list">
      {findings.map((finding) => (
        <article className="item" key={finding.id}>
          <div>
            <span className={`badge ${finding.severity}`}>{finding.severity}</span>
            <h3>{finding.vuln_id} · {finding.title}</h3>
            <p>{finding.description}</p>
          </div>
          <code>{finding.affected_files.join(', ')}</code>
        </article>
      ))}
    </div>
  );
}

function Fixes({ fixes }) {
  if (!fixes.length) return <Empty text="No fixes have been produced yet." />;
  return (
    <div className="list">
      {fixes.map((fix, index) => (
        <article className="item" key={`${fix.vulnerability_id}-${index}`}>
          <div>
            <span className={`badge ${fix.status}`}>{fix.status}</span>
            <h3>{fix.strategy}</h3>
            <p>{fix.notes || `${fix.operations.length} operation(s) planned.`}</p>
          </div>
          <code>{fix.file_path}</code>
        </article>
      ))}
    </div>
  );
}

function Validation({ validation, onRetry, loading }) {
  if (!validation) return <Empty text="Validation has not run yet." />;
  return (
    <div className="validation">
      <div className={`verdict ${validation.fixed ? 'pass' : 'fail'}`}>
        {validation.fixed ? <CheckCircle2 size={22} /> : <AlertTriangle size={22} />}
        <div>
          <strong>{validation.validation_status}</strong>
          <p>{validation.summary}</p>
        </div>
      </div>
      {validation.feedback_to_remediation ? <p className="feedback">{validation.feedback_to_remediation}</p> : null}
      {validation.pr_url ? <a className="pr-link" href={validation.pr_url}>Open pull request</a> : null}
      {!validation.fixed ? (
        <button className="secondary" onClick={onRetry} disabled={loading}>
          <RotateCw size={17} />
          Retry Agent B
        </button>
      ) : null}
    </div>
  );
}

function Trace({ trace }) {
  if (!trace.length) return <Empty text="Trace events will appear as the pipeline runs." />;
  return (
    <ol className="trace">
      {trace.map((event, index) => (
        <li key={`${event.timestamp}-${index}`}>
          <span>{event.step}</span>
          <strong>{event.status}</strong>
          <p>{event.message}</p>
        </li>
      ))}
    </ol>
  );
}

function Empty({ text }) {
  return <div className="empty">{text}</div>;
}

export default App;

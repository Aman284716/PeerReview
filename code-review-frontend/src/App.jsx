import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle2, Download, Github, Shield, Building2, Clock, FileText, AlertTriangle, TrendingUp, Eye, Users, Zap } from 'lucide-react';

const CodeReviewSystem = () => {
  const [formData, setFormData] = useState({
    github_url: '',
    industrial_standard: 'general' // Set to General Standards
  });
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);

  // Check API health on component mount
  useEffect(() => {
    checkHealth();
  }, []);

  const checkHealth = async () => {
    try {
      const response = await fetch('http://localhost:8000/health');
      const health = await response.json();
      setHealthStatus(health);
    } catch (err) {
      console.error('Health check failed:', err);
      setHealthStatus({ status: 'unhealthy' });
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    setResult(null);
    setReportData(null);

    try {
      const response = await fetch('http://localhost:8000/scan-standards', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Scan failed');
      }

      const data = await response.json();
      setResult(data);

      // Fetch the report data
      if (data.download_url) {
        const reportResponse = await fetch(`http://localhost:8000${data.download_url}`);
        const reportJson = await reportResponse.json();
        setReportData(reportJson);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownload = () => {
    if (result?.download_url && reportData) {
      const dataStr = JSON.stringify(reportData, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'code-review-report.json';
      link.click();
      URL.revokeObjectURL(url);
    }
  };

  const getSeverityBadge = (severity) => {
    const severityMap = {
      'HIGH': 'danger',
      'MEDIUM': 'warning',
      'LOW': 'info'
    };
    return severityMap[severity?.toUpperCase()] || 'secondary';
  };

  const getComplianceScoreBadge = (score) => {
    const numScore = parseInt(score);
    if (numScore >= 8) return 'success';
    if (numScore >= 6) return 'warning';
    return 'danger';
  };

  return (
    <div className="min-vh-100" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
      <div className="container py-5">
        {/* Header */}
        <div className="row justify-content-center mb-5">
          <div className="col-lg-10">
            <div className="text-center text-white mb-4">
              <div className="d-flex justify-content-center align-items-center mb-3">
                <Shield size={48} className="me-3" />
                <h1 className="display-4 fw-bold mb-0">Code Review System</h1>
              </div>
              <p className="lead">AI-powered standards scanning for GitHub repositories</p>
            </div>

            {/* Health Status */}
            {healthStatus && (
              <div className={`alert ${healthStatus.status === 'healthy' ? 'alert-success' : 'alert-warning'} d-flex align-items-center`}>
                {healthStatus.status === 'healthy' ? 
                  <CheckCircle2 size={20} className="me-2" /> : 
                  <AlertTriangle size={20} className="me-2" />
                }
                <span>
                  API Status: {healthStatus.status} 
                  {healthStatus.openai_client && ` | OpenAI: ${healthStatus.openai_client}`}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Main Content */}
        <div className="row justify-content-center">
          <div className="col-lg-8">
            <div className="card shadow-lg border-0">
              <div className="card-body p-5">
                <div onSubmit={handleSubmit}>
                  {/* GitHub URL Input */}
                  <div className="mb-4">
                    <label htmlFor="github_url" className="form-label d-flex align-items-center">
                      <Github size={20} className="me-2" />
                      <strong>GitHub Repository URL</strong>
                    </label>
                    <input
                      type="url"
                      className="form-control form-control-lg"
                      id="github_url"
                      name="github_url"
                      value={formData.github_url}
                      onChange={handleInputChange}
                      placeholder="https://github.com/username/repository.git"
                      required
                      disabled={isLoading}
                    />
                    <div className="form-text">
                      Enter the URL of a public GitHub repository to scan
                    </div>
                  </div>

                  {/* Submit Button */}
                  <div className="d-grid mb-4">
                    <button
                      type="button"
                      className="btn btn-primary btn-lg"
                      disabled={isLoading || !formData.github_url.trim()}
                      onClick={handleSubmit}
                    >
                      {isLoading ? (
                        <>
                          <div className="spinner-border spinner-border-sm me-2" role="status">
                            <span className="visually-hidden">Loading...</span>
                          </div>
                          Scanning Repository...
                        </>
                      ) : (
                        <>
                          <Shield size={20} className="me-2" />
                          Start Security Scan
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Loading State */}
                {isLoading && (
                  <div className="alert alert-info d-flex align-items-center">
                    <Clock size={20} className="me-2" />
                    <div>
                      <strong>Scanning in progress...</strong>
                      <div className="small">This may take a few minutes depending on repository size</div>
                    </div>
                  </div>
                )}

                {/* Error Display */}
                {error && (
                  <div className="alert alert-danger d-flex align-items-center">
                    <AlertCircle size={20} className="me-2" />
                    <div>
                      <strong>Scan Failed</strong>
                      <div className="small">{error}</div>
                    </div>
                  </div>
                )}

                {/* Success Result */}
                {result && !reportData && (
                  <div className="alert alert-success">
                    <div className="d-flex align-items-center">
                      <CheckCircle2 size={24} className="me-2" />
                      <div>
                        <strong>Scan Completed Successfully!</strong>
                        <div className="small">{result.message}</div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Report Display */}
                {reportData && (
                  <div className="mt-4">
                    {/* Report Header */}
                    <div className="d-flex justify-content-between align-items-center mb-4">
                      <h3 className="text-success mb-0">
                        <CheckCircle2 size={28} className="me-2" />
                        Scan Results
                      </h3>
                      <button
                        className="btn btn-outline-primary"
                        onClick={handleDownload}
                      >
                        <Download size={18} className="me-2" />
                        Export JSON
                      </button>
                    </div>

                    {/* Summary Cards */}
                    {reportData.scan_summary && (
                      <div className="row g-3 mb-4">
                        <div className="col-md-3">
                          <div className="card bg-primary text-white">
                            <div className="card-body text-center">
                              <FileText size={24} className="mb-2" />
                              <h5 className="card-title">{reportData.scan_summary.total_files_analyzed}</h5>
                              <p className="card-text small mb-0">Files Analyzed</p>
                            </div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="card bg-danger text-white">
                            <div className="card-body text-center">
                              <AlertTriangle size={24} className="mb-2" />
                              <h5 className="card-title">{reportData.scan_summary.high_severity_issues}</h5>
                              <p className="card-text small mb-0">High Severity</p>
                            </div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="card bg-warning text-white">
                            <div className="card-body text-center">
                              <Eye size={24} className="mb-2" />
                              <h5 className="card-title">{reportData.scan_summary.medium_severity_issues}</h5>
                              <p className="card-text small mb-0">Medium Severity</p>
                            </div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="card bg-info text-white">
                            <div className="card-body text-center">
                              <TrendingUp size={24} className="mb-2" />
                              <h5 className="card-title">{reportData.scan_summary.low_severity_issues}</h5>
                              <p className="card-text small mb-0">Low Severity</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Industry Standards Analysis */}
                    {reportData.industry_standards_analysis && !reportData.industry_standards_analysis.error && (
                      <div className="card mb-4">
                        <div className="card-header bg-primary text-white">
                          <h4 className="mb-0">
                            <Shield size={24} className="me-2" />
                            Industry Standards Analysis
                          </h4>
                          <small>General Standards</small>
                        </div>
                        <div className="card-body">
                          {reportData.industry_standards_analysis.findings && reportData.industry_standards_analysis.findings.map((finding, index) => (
                            <div key={index} className="card mb-3">
                              <div className="card-header d-flex justify-content-between align-items-center">
                                <div>
                                  <strong>{finding.file?.split('/').pop() || finding.file}</strong>
                                  <span className="badge bg-secondary ms-2">{finding.language}</span>
                                </div>
                                {finding.severity && (
                                  <span className={`badge bg-${getSeverityBadge(finding.severity)}`}>
                                    {finding.severity}
                                  </span>
                                )}
                              </div>
                              <div className="card-body">
                                <div className="row">
                                  {finding.security_issues && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-danger">Security Issues</h6>
                                      <p className="small">{finding.security_issues}</p>
                                    </div>
                                  )}
                                  {finding.quality_issues && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-warning">Quality Issues</h6>
                                      <p className="small">{finding.quality_issues}</p>
                                    </div>
                                  )}
                                  {finding.standard_violations && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-info">Standard Violations</h6>
                                      <p className="small">{finding.standard_violations}</p>
                                    </div>
                                  )}
                                  {finding.recommendations && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-success">Recommendations</h6>
                                      <p className="small">{finding.recommendations}</p>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Company Standards Analysis */}
                    {reportData.company_standards_analysis && !reportData.company_standards_analysis.error && (
                      <div className="card mb-4">
                        <div className="card-header bg-success text-white">
                          <h4 className="mb-0">
                            <Building2 size={24} className="me-2" />
                            Company Standards Analysis
                          </h4>
                          <small>Internal coding standards and policies</small>
                        </div>
                        <div className="card-body">
                          {reportData.company_standards_analysis.findings && reportData.company_standards_analysis.findings.map((finding, index) => (
                            <div key={index} className="card mb-3">
                              <div className="card-header d-flex justify-content-between align-items-center">
                                <div>
                                  <strong>{finding.file?.split('/').pop() || finding.file}</strong>
                                  <span className="badge bg-secondary ms-2">{finding.language}</span>
                                </div>
                                {finding.compliance_score && (
                                  <span className={`badge bg-${getComplianceScoreBadge(finding.compliance_score)}`}>
                                    Score: {finding.compliance_score}/10
                                  </span>
                                )}
                              </div>
                              <div className="card-body">
                                <div className="row">
                                  {finding.style_issues && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-warning">Style Issues</h6>
                                      <p className="small">{finding.style_issues}</p>
                                    </div>
                                  )}
                                  {finding.documentation_issues && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-info">Documentation Issues</h6>
                                      <p className="small">{finding.documentation_issues}</p>
                                    </div>
                                  )}
                                  {finding.policy_violations && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-danger">Policy Violations</h6>
                                      <p className="small">{finding.policy_violations}</p>
                                    </div>
                                  )}
                                  {finding.recommendations && (
                                    <div className="col-md-6 mb-3">
                                      <h6 className="text-success">Recommendations</h6>
                                      <p className="small">{finding.recommendations}</p>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    {reportData.recommendations && (
                      <div className="card">
                        <div className="card-header bg-info text-white">
                          <h4 className="mb-0">
                            <Zap size={24} className="me-2" />
                            Recommendations
                          </h4>
                        </div>
                        <div className="card-body">
                          {reportData.recommendations.priority_actions && reportData.recommendations.priority_actions.length > 0 && (
                            <div className="mb-3">
                              <h5 className="text-danger">Priority Actions</h5>
                              <ul className="list-group list-group-flush">
                                {reportData.recommendations.priority_actions.map((action, index) => (
                                  <li key={index} className="list-group-item border-0 px-0">
                                    <AlertTriangle size={16} className="text-danger me-2" />
                                    {action}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {reportData.recommendations.general_improvements && reportData.recommendations.general_improvements.length > 0 && (
                            <div>
                              <h5 className="text-info">General Improvements</h5>
                              <ul className="list-group list-group-flush">
                                {reportData.recommendations.general_improvements.map((improvement, index) => (
                                  <li key={index} className="list-group-item border-0 px-0">
                                    <TrendingUp size={16} className="text-info me-2" />
                                    {improvement}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Features Section */}
        <div className="row justify-content-center mt-5">
          <div className="col-lg-10">
            <div className="row g-4">
              <div className="col-md-4">
                <div className="card h-100 border-0 shadow-sm">
                  <div className="card-body text-center">
                    <Shield size={32} className="text-primary mb-3" />
                    <h5 className="card-title">Industry Standards</h5>
                    <p className="card-text text-muted">
                      Scan against General Standards for secure coding practices
                    </p>
                  </div>
                </div>
              </div>
              <div className="col-md-4">
                <div className="card h-100 border-0 shadow-sm">
                  <div className="card-body text-center">
                    <Building2 size={32} className="text-success mb-3" />
                    <h5 className="card-title">Company Standards</h5>
                    <p className="card-text text-muted">
                      Analyze code against your company-specific coding standards
                    </p>
                  </div>
                </div>
              </div>
              <div className="col-md-4">
                <div className="card h-100 border-0 shadow-sm">
                  <div className="card-body text-center">
                    <FileText size={32} className="text-info mb-3" />
                    <h5 className="card-title">Detailed Reports</h5>
                    <p className="card-text text-muted">
                      Get comprehensive JSON reports with findings and recommendations
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CodeReviewSystem;

import { useState, useEffect } from 'react';
import {
  AppBar, Toolbar, Typography, Button, Container, Box, TextField,
  CircularProgress, Card, CardContent, Grid, Chip, List,
  ListItem, ListItemIcon, ListItemText, Paper,
} from '@mui/material';
import { styled } from '@mui/material/styles';
import { Tabs, Tab, Select, MenuItem, FormControl, InputLabel } from '@mui/material';
import { Lock, Github, Shield, Building, FileText, AlertCircle, Clock, CheckCircle, Download, Edit2, AlertTriangle, ArrowUp } from 'lucide-react';
import './CodeReviewSystem.css';
import { ArrowDown} from 'lucide-react';

const StyledCard = styled(Card)(({ theme }) => ({
  marginBottom: theme.spacing(2),
  border: '1px solid #e0e0e0',
  borderRadius: '8px',
}));

const StyledPaper = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(3),
  border: '1px solid #e0e0e0',
  borderRadius: '8px',
  backgroundColor: '#ffffff',
}));

const CodeReviewSystem = () => {
  const [formData, setFormData] = useState({
    github_url: '',
    industrial_standard: 'general',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState('industry');
  const [expandedCards, setExpandedCards] = useState({});

  const getShortFilePath = (fullPath) => {
    if (!fullPath) return '';
    // Normalize slashes
    const parts = fullPath.replace(/\\/g, '/').split('/');
    // Take last 3 parts: e.g. "public_safety_app/PublicSafetyApplication.java"
    const lastParts = parts.slice(-2);
    return lastParts.join('/');
  };
  
  const toggleExpand = (index) => {
    setExpandedCards(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };  
  const handleAnalysisChange = (event, newValue) => {
    if (typeof newValue === 'string') {
      setSelectedAnalysis(prev => (prev === newValue ? null : newValue));
    }
  };
  
  const handleDropdownChange = (event) => {
    setSelectedAnalysis(event.target.value);
    setSelectedAnalysis(prev => (prev === value ? null : value));
  };

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
    setFormData((prev) => ({
      ...prev,
      [name]: value,
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
      HIGH: { backgroundColor: '#FFF5F5', color: '#9B2C2C' }, // Red, like bg-red-100
      MEDIUM: { backgroundColor: '#FFFFF0', color: '#975A16' }, // Yellow, like bg-yellow-100
      LOW: { backgroundColor: '#EBF8FF', color: '#2B6CB0' }, // Blue, like bg-blue-100
    };
    return severityMap[severity?.toUpperCase()] || { backgroundColor: '#F7FAFC', color: '#2D3748' }; // Fallback, like bg-gray-100
  };

  const getComplianceScoreBadge = (score) => {
    const numScore = parseInt(score);
    if (numScore >= 8) return { backgroundColor: '#E6FFFA', color: '#000' }; // Teal, like bg-teal-100
    if (numScore >= 6) return { backgroundColor: '#FFFFF0', color: '#975A16' }; // Yellow
    return { backgroundColor: '#FFF5F5', color: '#9B2C2C' }; // Red
  };

  return (
    <div className="template-container">
      <StyledCard className="template-card">
        <AppBar position="static" className="navbar" sx={{ backgroundColor: '#319795' }}>
          <Toolbar>
            <Box display="flex" alignItems="center">
              <Lock className="mr-2" size={24} color="white" />
              <Typography variant="h6" color="white">Peer Review</Typography>
            </Box>
            <Box sx={{ flexGrow: 1 }} />
          </Toolbar>
        </AppBar>

        <Container maxWidth="lg" sx={{ py: 4 }}>
          <Typography variant="h4" className="editor-title">Peer Review System</Typography>
          <Typography variant="subtitle1" className="form-label">
            AI-powered standards scanning for GitHub repositories
          </Typography>

          {healthStatus && (
            <div className={`status-message ${healthStatus.status === 'healthy' ? 'success-message' : 'warning-message'}`}>
              <Box display="flex" alignItems="center">
                {healthStatus.status === 'healthy' ? <CheckCircle size={20} className="mr-2" /> : <AlertCircle size={20} className="mr-2" />}
                <Typography>API Status: {healthStatus.status}</Typography>
                {healthStatus.openai_client && <Typography> | OpenAI: {healthStatus.openai_client}</Typography>}
              </Box>
            </div>
          )}

          <StyledPaper className="form-group">
            <Typography variant="h6" className="form-label">
              <Github size={20} className="mr-2" /> GitHub Repository URL
            </Typography>
            <TextField
              fullWidth
              variant="outlined"
              name="github_url"
              value={formData.github_url}
              onChange={handleInputChange}
              placeholder="https://github.com/username/repository.git"
              disabled={isLoading}
              className="select-input"
            />
            <Typography variant="caption" className="upload-hint">
              Enter the URL of a public GitHub repository to scan
            </Typography>
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
              <Button
                variant="contained"
                className="action-button"
                onClick={handleSubmit}
                disabled={isLoading || !formData.github_url.trim()}
                startIcon={isLoading ? <CircularProgress size={20} /> : <Shield size={20} />}
                sx={{ backgroundColor: '#E6FFFA', color: '#000', '&:hover': { backgroundColor: '#B2F5EA' } }}
              >
                {isLoading ? 'Scanning Repository...' : 'Start Security Scan'}
              </Button>
            </Box>
          </StyledPaper>

          {isLoading && (
            <div className="status-message info-message">
              <Box display="flex" alignItems="center">
                <Clock size={20} className="mr-2" />
                <Box>
                  <Typography variant="subtitle2">Scanning in progress...</Typography>
                  <Typography variant="caption">This may take a few minutes depending on repository size</Typography>
                </Box>
              </Box>
            </div>
          )}

          {error && (
            <div className="status-message error-message">
              <Box display="flex" alignItems="center">
                <AlertCircle size={20} className="mr-2" />
                <Box>
                  <Typography variant="subtitle2">Scan Failed</Typography>
                  <Typography variant="caption">{error}</Typography>
                </Box>
              </Box>
            </div>
          )}

          {result && !reportData && (
            <div className="status-message success-message">
              <Box display="flex" alignItems="center">
                <CheckCircle size={20} className="mr-2" />
                <Box>
                  <Typography variant="subtitle2">Scan Completed Successfully!</Typography>
                  <Typography variant="caption">{result.message}</Typography>
                </Box>
              </Box>
            </div>
          )}

          {reportData && (
            <Box className="editor-section">
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
                <Typography variant="h5" className="editor-title">
                  <CheckCircle size={20} className="mr-2" /> Scan Results
                </Typography>
                <Button
                  variant="outlined"
                  className="action-button"
                  onClick={handleDownload}
                  startIcon={<Download size={20} />}
                  sx={{ borderColor: '#E6FFFA', color: '#319795', '&:hover': { backgroundColor: '#E6FFFA' } }}
                >
                  Export JSON
                </Button>
              </Box>

              {reportData.scan_summary && (
                <Grid container spacing={2} className="templates-grid">
                  <Grid item xs={12} sm={6} md={3}>
                    <StyledCard>
                      <CardContent>
                        <Typography variant="h6" className="form-label">
                          <FileText size={20} className="mr-2" /> Files Analyzed
                        </Typography>
                        <Typography>Total: <strong>{reportData.scan_summary.total_files_analyzed}</strong></Typography>
                      </CardContent>
                    </StyledCard>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <StyledCard>
                      <CardContent>
                        <Typography variant="h6" className="form-label">
                          <AlertTriangle size={20} className="mr-2" /> High Severity
                        </Typography>
                        <Typography>Total: <strong>{reportData.scan_summary.high_severity_issues}</strong></Typography>
                      </CardContent>
                    </StyledCard>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <StyledCard>
                      <CardContent>
                        <Typography variant="h6" className="form-label">
                          <Edit2 size={20} className="mr-2" /> Medium Severity
                        </Typography>
                        <Typography>Total: <strong>{reportData.scan_summary.medium_severity_issues}</strong></Typography>
                      </CardContent>
                    </StyledCard>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <StyledCard>
                      <CardContent>
                        <Typography variant="h6" className="form-label">
                          <FileText size={20} className="mr-2" /> Low Severity
                        </Typography>
                        <Typography>Total: <strong>{reportData.scan_summary.low_severity_issues}</strong></Typography>
                      </CardContent>
                    </StyledCard>
                  </Grid>
                </Grid>
              )}

    {reportData && (
      <>
        {/* Tabs for larger screens */}
        <Tabs
      value={selectedAnalysis}
      aria-label="Analysis Tabs"
      sx={{ borderBottom: 1, borderColor: 'divider', display: { xs: 'none', md: 'flex' }, mb: 3 }}
      textColor="primary"
      indicatorColor="primary"
    >
      <Tab
        label="Industry Standards"
        value="industry"
        onClick={() => setSelectedAnalysis(prev => (prev === 'industry' ? null : 'industry'))}
      />
      <Tab
        label="Company Standards"
        value="company"
        onClick={() => setSelectedAnalysis(prev => (prev === 'company' ? null : 'company'))}
      />
    </Tabs>

    {/* Dropdown for smaller screens */}
    <FormControl
      fullWidth
      sx={{ mb: 3, display: { xs: 'block', md: 'none' } }}
      size="small"
    >
      <InputLabel id="analysis-select-label">Select Analysis</InputLabel>
      <Select
        labelId="analysis-select-label"
        id="analysis-select"
        value={selectedAnalysis}
        label="Select Analysis"
        onChange={handleDropdownChange}
      >
        <MenuItem value="industry">Industry Standards</MenuItem>
        <MenuItem value="company">Company Standards</MenuItem>
      </Select>
    </FormControl>

    {/* Render Industry Standards Analysis */}
    {selectedAnalysis === 'industry' && reportData.industry_standards_analysis && !reportData.industry_standards_analysis.error && (
      <Box sx={{ borderLeft: '4px solid #319795', p: 2, backgroundColor: '#F7FAFC' }}>
        <Typography variant="h6" sx={{ fontWeight: 'bold', mb: 2 }}>
          <Shield size={20} className="mr-2" /> Industry Standards Analysis
        </Typography>
        <Typography variant="caption" className="upload-hint" sx={{ mb: 2 }}>
          General Standards
        </Typography>
        {reportData.industry_standards_analysis.findings?.map((finding, index) => (
          <StyledCard key={index} className="template-item">
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" className="template-item-header">
                <Box display="flex" alignItems="center" sx={{ flexGrow: 1 }}>
                  {/* File path: show only last two folders + filename */}
                  <Typography variant="subtitle1" className="template-name" sx={{ mr: 1, fontWeight: 'bold' }}>
                    {getShortFilePath(finding.file)}
                  </Typography>
                  <Chip label={finding.language} size="small" sx={{ backgroundColor: '#F7FAFC', color: '#2D3748' }} />
                  {finding.severity && (
                  <Chip label={finding.severity} size='small' sx={getSeverityBadge(finding.severity)} />
                )}
                </Box>
                {/* Expand/Collapse arrow */}
                <Button
                  size="small"
                  onClick={() => toggleExpand(index)}
                  aria-expanded={!!expandedCards[index]}
                  aria-label={expandedCards[index] ? 'Collapse details' : 'Expand details'}
                  sx={{ minWidth: 'auto', padding: 0 }}
                >
                  {expandedCards[index] ? <ArrowUp /> : <ArrowDown />}
                </Button>
              </Box       >

              {/* Conditionally render the full details if expanded */}
              {expandedCards[index] && (
                <Box className="template-preview" sx={{ mt: 2 }}>
                  {finding.security_issues && (
                    <Box>
                      <Typography variant="subtitle2">Security Issues</Typography>
                      <Typography variant="body2" className="upload-hint">{finding.security_issues}</Typography>
                    </Box>
                  )}
                  {finding.quality_issues && (
                    <Box mt={2}>
                      <Typography variant="subtitle2">Quality Issues</Typography>
                      <Typography variant="body2" className="upload-hint">{finding.quality_issues}</Typography>
                    </Box>
                  )}
                  {finding.standard_violations && (
                    <Box mt={2}>
                      <Typography variant="subtitle2">Standard Violations</Typography>
                      <Typography variant="body2" className="upload-hint">{finding.standard_violations}</Typography>
                    </Box>
                  )}
                  {finding.recommendations && (
                    <Box mt={2}>
                      <Typography variant="subtitle2">Recommendations</Typography>
                      <Typography variant="body2" className="upload-hint">{finding.recommendations}</Typography>
                    </Box>
                  )}
                </Box>
              )}
            </CardContent>
          </StyledCard>
        ))}
      </Box>
    )}

  {selectedAnalysis === 'company' && reportData.company_standards_analysis && !reportData.company_standards_analysis.error && (
    <Box sx={{ borderLeft: '4px solid #6B46C1', p: 2, backgroundColor: '#F7FAFC' }}>
      <Typography variant="h6" sx={{ fontWeight: 'bold', mb: 2 }}>
        <Building size={20} className="mr-2" /> Company Standards Analysis
      </Typography>
      <Typography variant="caption" className="upload-hint" sx={{ mb: 2 }}>
        Internal coding standards and policies
      </Typography>
      {reportData.company_standards_analysis.findings?.map((finding, index) => (
        <StyledCard key={index} className="template-item">
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" className="template-item-header">
              <Box display="flex" alignItems="center" sx={{ flexGrow: 1 }}>
                {/* File path: show only last two folders + filename */}
                <Typography variant="subtitle1" className="template-name" sx={{ mr: 1, fontWeight: 'bold' }}>
                  {getShortFilePath(finding.file)}
                </Typography>
                <Chip label={finding.language} size="small" sx={{ backgroundColor: '#F7FAFC', color: '#2D3748' }} />
                {finding.compliance_score && (
                  <Chip
                    label={`Score: ${finding.compliance_score}/10`}
                    sx={getComplianceScoreBadge(finding.compliance_score)}
                  />
                )}
              </Box>
              {/* Expand/Collapse arrow */}
              <Button
                size="small"
                onClick={() => toggleExpand(index)}
                aria-expanded={!!expandedCards[index]}
                aria-label={expandedCards[index] ? 'Collapse details' : 'Expand details'}
                sx={{ minWidth: 'auto', padding: 0 }}
              >
                {expandedCards[index] ? <ArrowUp /> : <ArrowDown />}
              </Button>
            </Box>

            {/* Conditionally render the full details if expanded */}
            {expandedCards[index] && (
              <Box className="template-preview" sx={{ mt: 2 }}>
                {finding.style_issues && (
                  <Box>
                    <Typography variant="subtitle2">Style Issues</Typography>
                    <Typography variant="body2" className="upload-hint">{finding.style_issues}</Typography>
                  </Box>
                )}
                {finding.documentation_issues && (
                  <Box mt={2}>
                    <Typography variant="subtitle2">Documentation Issues</Typography>
                    <Typography variant="body2" className="upload-hint">{finding.documentation_issues}</Typography>
                  </Box>
                )}
                {finding.policy_violations && (
                  <Box mt={2}>
                    <Typography variant="subtitle2">Policy Violations</Typography>
                    <Typography variant="body2" className="upload-hint">{finding.policy_violations}</Typography>
                  </Box>
                )}
                {finding.recommendations && (
                  <Box mt={2}>
                    <Typography variant="subtitle2">Recommendations</Typography>
                    <Typography variant="body2" className="upload-hint">{finding.recommendations}</Typography>
                  </Box>
                )}
              </Box>
            )}
          </CardContent>
        </StyledCard>
      ))}
    </Box>
    )}
  </>
)}


              {reportData.recommendations && (
                <Box mt={4} className="templates-section">
                  <Typography variant="h5" className="editor-title">
                    <Edit2 size={20} className="mr-2" /> Recommendations
                  </Typography>
                  {reportData.recommendations.priority_actions?.length > 0 && (
                    <Box>
                      <Typography variant="h6" className="form-label">Priority Actions</Typography>
                      <List>
                        {reportData.recommendations.priority_actions.map((action, index) => (
                          <ListItem key={index}>
                            <ListItemIcon>
                              <AlertTriangle size={20} />
                            </ListItemIcon>
                            <ListItemText primary={action} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                  {reportData.recommendations.general_improvements?.length > 0 && (
                    <Box>
                      <Typography variant="h6" className="form-label">General Improvements</Typography>
                      <List>
                        {reportData.recommendations.general_improvements.map((improvement, index) => (
                          <ListItem key={index}>
                            <ListItemIcon>
                              <FileText size={20} />
                            </ListItemIcon>
                            <ListItemText primary={improvement} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </Box>
              )}
            </Box>
          )}

          <Grid container spacing={2} className="templates-grid">
            <Grid item xs={12} sm={4}>
              <StyledCard>
                <CardContent>
                  <Typography variant="h6" className="form-label">
                    <Shield size={20} className="mr-2" /> Industry Standards
                  </Typography>
                  <Typography variant="body2" className="upload-hint">
                    Scan against General Standards for secure coding practices
                  </Typography>
                </CardContent>
              </StyledCard>
            </Grid>
            <Grid item xs={12} sm={4}>
              <StyledCard>
                <CardContent>
                  <Typography variant="h6" className="form-label">
                    <Building size={20} className="mr-2" /> Company Standards
                  </Typography>
                  <Typography variant="body2" className="upload-hint">
                    Analyze code against your company-specific coding standards
                  </Typography>
                </CardContent>
              </StyledCard>
            </Grid>
            <Grid item xs={12} sm={4}>
              <StyledCard>
                <CardContent>
                  <Typography variant="h6" className="form-label">
                    <FileText size={20} className="mr-2" /> Detailed Reports
                  </Typography>
                  <Typography variant="body2" className="upload-hint">
                    Get comprehensive JSON reports with findings and recommendations
                  </Typography>
                </CardContent>
              </StyledCard>
            </Grid>
          </Grid>
        </Container>
      </StyledCard>
    </div>
  );
};

export default CodeReviewSystem;
import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Button, FormControl, InputLabel, Select, MenuItem,
  Alert, CircularProgress, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Card, CardContent
} from '@mui/material';
import { styled } from '@mui/material/styles';
import { Upload, FileText } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <Alert severity="error" sx={{ m: 2 }}>
          Something went wrong: {this.state.error?.message || 'Unknown error'}
        </Alert>
      );
    }
    return this.props.children;
  }
}

const StyledPaper = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(3),
  border: '1px solid #e0e0e0',
  borderRadius: '8px',
  backgroundColor: '#ffffff',
}));
const StyledCard = styled(Card)(({ theme }) => ({
  marginBottom: theme.spacing(2),
  border: '1px solid #e0e0e0',
  borderRadius: '8px',
}));

const AdminPanel = () => {
  const navigate = useNavigate();
  const [standards, setStandards] = useState(null);
  const [standardType, setStandardType] = useState('industry');
  const [file, setFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [report, setReport] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    console.log('AdminPanel.jsx: token=', token);
    if (!token) {
      setError('Please log in to access the admin panel.');
      navigate('/login');
    } else {
      fetchStandards();
    }
  }, [navigate]);

  const fetchStandards = async () => {
    setIsLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('admin_token');
      if (!token) {
        throw new Error('No authentication token found');
      }
      const response = await fetch('http://localhost:8000/standards', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        if (response.status === 401) {
          setError('Session expired. Please log in again.');
          localStorage.removeItem('admin_token');
          navigate('/login');
          return;
        }
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to fetch standards');
      }
      const data = await response.json();
      console.log('Standards fetched:', data);
      setStandards(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to upload');
      return;
    }
    if (!file.name.endsWith('.docx')) {
      setError('Only .docx files are supported');
      return;
    }
    setIsLoading(true);
    setError('');
    setSuccess('');
    const formData = new FormData();
    formData.append('file', file);
    formData.append('standard_type', standardType);
    try {
      const token = localStorage.getItem('admin_token');
      if (!token) {
        throw new Error('No authentication token found');
      }
      const response = await fetch('http://localhost:8000/upload-standard', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      if (!response.ok) {
        if (response.status === 401) {
          setError('Session expired. Please log in again.');
          localStorage.removeItem('admin_token');
          navigate('/login');
          return;
        }
        const errorData = await response.json();
        throw new Error(errorData.detail || 'File upload failed');
      }
      setSuccess('File uploaded successfully');
      setFile(null);
      fetchStandards();
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleScan = async () => {
    setIsLoading(true);
    setError('');
    setReport(null);
    try {
      const token = localStorage.getItem('admin_token');
      if (!token) {
        throw new Error('No authentication token found');
      }
      const response = await fetch('http://localhost:8000/scan-standards-documents', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        if (response.status === 401) {
          setError('Session expired. Please log in again.');
          localStorage.removeItem('admin_token');
          navigate('/login');
          return;
        }
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to scan standards');
      }
      const data = await response.json();
      setReport(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const renderRules = (rules) => {
    if (!rules || rules.length === 0) {
      return <li>No specific rules</li>;
    }
    return rules.map((rule, index) => (
      <li key={index}>
        {rule.text.startsWith('Error reading') || rule.text.startsWith('No rules found') ? (
          <span style={{ color: 'red' }}>{rule.text} (Source: {rule.file})</span>
        ) : (
          <span>{rule.text} (Source: {rule.file})</span>
        )}
      </li>
    ));
  };

  return (
    <ErrorBoundary>
      <Box sx={{ minHeight: '100vh', bgcolor: '#f5f5f5', p: 4 }}>
        <Typography variant="h4" sx={{ mb: 3, color: '#004D40' }}>
          Admin Panel - Standards Management
        </Typography>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} aria-live="assertive">
            {error}
          </Alert>
        )}
        {success && (
          <Alert severity="success" sx={{ mb: 2 }} aria-live="assertive">
            {success}
          </Alert>
        )}
        <StyledPaper sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
            <Upload size={20} style={{ marginRight: 8 }} /> Upload Standard Document
          </Typography>
          <Box component="form" onSubmit={handleFileUpload}>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel id="standard-type-label">Standard Type</InputLabel>
              <Select
                labelId="standard-type-label"
                value={standardType}
                onChange={(e) => setStandardType(e.target.value)}
                label="Standard Type"
                aria-describedby="standard-type-helper"
              >
                <MenuItem value="industry">Industry Standard</MenuItem>
                <MenuItem value="company">Company Specific</MenuItem>
              </Select>
            </FormControl>
            <input
              type="file"
              accept=".docx"
              onChange={(e) => setFile(e.target.files[0])}
              style={{ marginBottom: 16 }}
              id="file-upload"
              aria-label="Upload .docx file"
            />
            <Button
              variant="contained"
              type="submit"
              disabled={isLoading || !file}
              startIcon={isLoading ? <CircularProgress size={20} /> : <Upload size={20} />}
              sx={{ bgcolor: '#319795', '&:hover': { bgcolor: '#00695C' } }}
              aria-label="Upload selected file"
            >
              {isLoading ? 'Uploading...' : 'Upload File'}
            </Button>
          </Box>
        </StyledPaper>
        <StyledPaper sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
            <FileText size={20} style={{ marginRight: 8 }} /> Standards Dashboard
          </Typography>
          {isLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center' }}>
              <CircularProgress aria-label="Loading standards" />
            </Box>
          ) : standards && typeof standards === 'object' && Object.keys(standards).length > 0 ? (
            <TableContainer>
              <Table aria-label="Standards comparison table">
                <TableHead>
                  <TableRow>
                    <TableCell>Language</TableCell>
                    <TableCell>Industry Standards</TableCell>
                    <TableCell>Company Standards</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {Object.keys(standards).map((language) => (
                    <TableRow key={language}>
                      <TableCell>{language}</TableCell>
                      <TableCell>
                        <ul>{renderRules(standards[language]?.industry)}</ul>
                      </TableCell>
                      <TableCell>
                        <ul>{renderRules(standards[language]?.company)}</ul>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Typography variant="body2" color="textSecondary">
              No standards loaded. Please upload .docx files or check server logs.
            </Typography>
          )}
        </StyledPaper>
        <StyledPaper>
          <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
            <FileText size={20} style={{ marginRight: 8 }} /> Scan Standards
          </Typography>
          <Button
            variant="contained"
            onClick={handleScan}
            disabled={isLoading}
            startIcon={isLoading ? <CircularProgress size={20} /> : <FileText size={20} />}
            sx={{ bgcolor: '#319795', '&:hover': { bgcolor: '#00695C' } }}
            aria-label="Scan all standards"
          >
            {isLoading ? 'Scanning...' : 'Scan All Standards'}
          </Button>
          {report && (
            <StyledCard sx={{ mt: 2 }}>
              <CardContent>
                <Typography variant="subtitle1">Scan Report</Typography>
                <Typography variant="body2">
                  Total Standards Scanned: {report.total_standards}
                </Typography>
                <Typography variant="body2">
                  Industry Standards: {report.industry_standards_count}
                </Typography>
                <Typography variant="body2">
                  Company Standards: {report.company_standards_count}
                </Typography>
                <Typography variant="body2">
                  Details: {report.details}
                </Typography>
                {report.analysis_results && (
                  <>
                    <Typography variant="subtitle2" sx={{ mt: 2 }}>
                      File Analysis
                    </Typography>
                    <ul>
                      {report.analysis_results.map((result, index) => (
                        <li key={index}>
                          {result.file} ({result.type}): {result.status === 'error' ? result.details : result.details}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </CardContent>
            </StyledCard>
          )}
        </StyledPaper>
      </Box>
    </ErrorBoundary>
  );
};

export default AdminPanel;
import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  Button,
  Typography,
  Paper,
  InputAdornment,
  IconButton,
  Alert,
  CircularProgress,
  Link,
} from '@mui/material';
import PersonIcon from '@mui/icons-material/Person';
import LockIcon from '@mui/icons-material/Lock';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import logo from '../assets/logo.png';
import { useNavigate } from 'react-router-dom';

const Login = () => {
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [formData, setFormData] = useState({ username: '', password: '' });
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    if (token) {
      setIsAuthenticated(true);
    }
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    if (error) setError('');
  };

  const handleLogin = () => {
    if (!formData.username || !formData.password) {
      setError('Please enter both username and password');
      return;
    }

    setIsLoading(true);
    setError('');

    //Credentials
    const hardcodedUsername = 'admin';
    const hardcodedPassword = 'password123';

    setTimeout(() => {
      if (
        formData.username === hardcodedUsername &&
        formData.password === hardcodedPassword
      ) {
        localStorage.setItem('admin_token', 'token_for_demo'); 
        setIsAuthenticated(true);
        navigate('/');
      } else {
        setError('Invalid username or password');
      }
      setIsLoading(false);
    }, 1000);
  };

  const handleLogout = () => {
    localStorage.removeItem('admin_token');
    setIsAuthenticated(false);
    setFormData({ username: '', password: '' });
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleLogin();
    }
  };

  const handleClickShowPassword = () => {
    setShowPassword((prev) => !prev);
  };
  const handleMouseDownPassword = (event) => {
    event.preventDefault();
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        bgcolor: '#319795',
        p: 2,
      }}
    >
      <Paper
        elevation={6}
        sx={{
          display: 'flex',
          width: { xs: '100%', sm: '90%', md: '800px', lg: '900px' },
          maxWidth: '900px',
          overflow: 'hidden',
          borderRadius: 3,
          flexDirection: { xs: 'column', md: 'row' },
        }}
      >
        {/* Left side: Logo */}
        <Box
          sx={{
            flex: 1,
            bgcolor: 'white',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            p: { xs: 3, md: 4 },
            borderRight: { xs: 'none', md: '1px solid #e0e0e0' },
            borderBottom: { xs: '1px solid #e0e0e0', md: 'none' },
          }}
        >
          <img
            src={logo}
            alt="Company Logo"
            style={{
              maxWidth: '50%',
              maxHeight: '200px',
              height: 'auto',
              objectFit: 'contain',
            }}
          />
        </Box>

        {/* Right side: Form */}
        <Box
          sx={{
            flex: 1,
            bgcolor: 'white',
            p: { xs: 3, md: 5 },
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
          }}
        >
          <Typography
            component="h1"
            variant="h5"
            sx={{
              mb: 3,
              textAlign: 'center',
              fontWeight: 'bold',
              color: '#004D40',
            }}
          >
            Sign In
          </Typography>

          {error && (
            <Alert severity="error" sx={{ width: '100%', mb: 2 }}>
              {error}
            </Alert>
          )}

          <Box component="form" noValidate>
            <TextField
              variant="standard"
              margin="normal"
              required
              fullWidth
              id="username"
              name="username"
              label="Username"
              value={formData.username}
              onChange={handleInputChange}
              onKeyPress={handleKeyPress}
              autoComplete="username"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <PersonIcon sx={{ color: '#00796B' }} />
                  </InputAdornment>
                ),
              }}
              sx={{
                mb: 3,
                '& .MuiInputBase-root': { color: '#333' },
                '& .MuiInput-underline:before': { borderBottomColor: '#ccc' },
                '& .MuiInput-underline:hover:not(.Mui-disabled):before': {
                  borderBottomColor: '#00796B',
                },
                '& .MuiInput-underline:after': { borderBottomColor: '#00796B' },
                '& label': { color: '#888' },
                '& label.Mui-focused': { color: '#00796B' },
              }}
            />

            <TextField
              variant="standard"
              margin="normal"
              required
              fullWidth
              id="password"
              name="password"
              label="Password"
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={handleInputChange}
              onKeyPress={handleKeyPress}
              autoComplete="current-password"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <LockIcon sx={{ color: '#00796B' }} />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      aria-label="toggle password visibility"
                      onClick={handleClickShowPassword}
                      onMouseDown={handleMouseDownPassword}
                      edge="end"
                      sx={{ color: '#00796B' }}
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{
                mb: 3,
                '& .MuiInputBase-root': { color: '#333' },
                '& .MuiInput-underline:before': { borderBottomColor: '#ccc' },
                '& .MuiInput-underline:hover:not(.Mui-disabled):before': {
                  borderBottomColor: '#00796B',
                },
                '& .MuiInput-underline:after': { borderBottomColor: '#00796B' },
                '& label': { color: '#888' },
                '& label.Mui-focused': { color: '#00796B' },
              }}
            />

            <Box
              sx={{
                display: 'flex',
                justifyContent: 'flex-end',
                alignItems: 'center',
                mt: 1,
                mb: 2,
              }}
            >
              <Link
                href="#"
                variant="body2"
                sx={{
                  color: '#00796B',
                  '&:hover': { textDecoration: 'underline' },
                }}
              >
                Forgot password?
              </Link>
            </Box>

            <Button
              variant="contained"
              fullWidth
              onClick={handleLogin}
              disabled={isLoading || !formData.username || !formData.password}
              size="large"
              sx={{
                mt: 3,
                mb: 2,
                py: 1.5,
                bgcolor: '#00796B',
                fontWeight: 'bold',
                fontSize: '1rem',
                textTransform: 'none',
                '&:hover': {
                  bgcolor: '#00695C',
                },
                '&:disabled': {
                  bgcolor: 'grey.300',
                  boxShadow: 'none',
                },
              }}
            >
              {isLoading ? (
                <>
                  <CircularProgress size={20} color="inherit" sx={{ mr: 1 }} />
                  Signing In...
                </>
              ) : (
                'Sign In'
              )}
            </Button>
          </Box>
        </Box>
      </Paper>
    </Box>
  );
};

export default Login;

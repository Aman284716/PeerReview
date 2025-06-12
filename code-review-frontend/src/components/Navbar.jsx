import React from 'react';
import { AppBar, Toolbar, Typography, Box } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import logo_white from '../assets/logo_white.png';

const Navbar = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.clear();   // or localStorage.removeItem('yourCredentialKey') if you want to be more specific
    navigate('/login');     // redirect to login page
  };

  return (
    <AppBar position="static" sx={{ backgroundColor: 'black' }}>
      <Toolbar sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <img
            src={logo_white}
            alt="Logo"
            style={{ height: 60, marginRight: 10 }}
          />
        </Box>
        <Box sx={{ display: 'flex', gap: 3 }}>
          <Typography variant="body1" sx={{ cursor: 'pointer' }}>
            Dashboard
          </Typography>
          <Typography variant="body1" sx={{ cursor: 'pointer' }}>
            Profile
          </Typography>
          <Typography variant="body1" sx={{ cursor: 'pointer' }}>
            Settings
          </Typography>
          <Typography
            variant="body1"
            sx={{ cursor: 'pointer' }}
            onClick={handleLogout}
          >
            Logout
          </Typography>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;

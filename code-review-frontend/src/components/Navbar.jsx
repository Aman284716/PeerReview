import React, { useEffect, useState } from 'react';
import { AppBar, Toolbar, Typography, Box, IconButton, Menu, MenuItem } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import MenuIcon from '@mui/icons-material/Menu';
import logo_white from '../assets/logo_white.png';

const Navbar = () => {
  const navigate = useNavigate();
  const [isAdmin, setIsAdmin] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    setIsAdmin(token === 'token_for_demo');
    console.log('Navbar.jsx: token=', token, 'isAdmin=', isAdmin);
  }, []);

  const handleMenuOpen = (event) => setAnchorEl(event.currentTarget);
  const handleMenuClose = () => setAnchorEl(null);

  const handleLogout = () => {
    console.log('Navbar.jsx: Logging out');
    localStorage.removeItem('admin_token');
    navigate('/login');
  };

  const navItems = [
    { label: 'Dashboard', path: '/dashboard' },
    { label: 'Profile', path: '/profile' },
    { label: 'Settings', path: '/settings' },
    ...(isAdmin ? [{ label: 'Admin', path: '/admin' }] : []),
    { label: 'Logout', action: handleLogout },
  ];

  return (
    <AppBar position="static" sx={{ backgroundColor: 'black' }}>
      <Toolbar sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <img
            src={logo_white}
            alt="Company Logo"
            style={{ height: 60, marginRight: 10 }}
            aria-label="Company Logo"
          />
        </Box>
        <Box sx={{ display: { xs: 'none', md: 'flex' }, gap: 3 }}>
          {navItems.map((item, index) => (
            <Typography
              key={index}
              variant="body1"
              sx={{ cursor: 'pointer', color: '#fff', '&:hover': { textDecoration: 'underline' } }}
              onClick={() => (item.action ? item.action() : navigate(item.path))}
              role="button"
              tabIndex={0}
              aria-label={item.label}
              onKeyDown={(e) => e.key === 'Enter' && (item.action ? item.action() : navigate(item.path))}
            >
              {item.label}
            </Typography>
          ))}
        </Box>
        <Box sx={{ display: { xs: 'flex', md: 'none' } }}>
          <IconButton
            edge="end"
            color="inherit"
            aria-label="Open navigation menu"
            onClick={handleMenuOpen}
          >
            <MenuIcon />
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={open}
            onClose={handleMenuClose}
            anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
            transformOrigin={{ vertical: 'top', horizontal: 'right' }}
          >
            {navItems.map((item, index) => (
              <MenuItem
                key={index}
                onClick={() => {
                  item.action ? item.action() : navigate(item.path);
                  handleMenuClose();
                }}
              >
                {item.label}
              </MenuItem>
            ))}
          </Menu>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
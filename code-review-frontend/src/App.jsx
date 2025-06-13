import React from 'react';
import { useLocation } from 'react-router-dom';
import { Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from './components/LoginPage';
import CodeReviewSystem from './components/CodeReviewSystem';
import AdminPanel from './components/AdminPanel';
import Navbar from './components/Navbar';
import './index.css';

function App() {
  const token = localStorage.getItem('admin_token');
  const isAuthenticated = !!token;
  // Hardcoded token grants admin access
  const isAdmin = token === 'token_for_demo';
  const location = useLocation();
  const hideNavbarRoutes = ['/login'];
  const shouldShowNavbar = !hideNavbarRoutes.includes(location.pathname);

  console.log('App.jsx: token=', token, 'isAuthenticated=', isAuthenticated, 'isAdmin=', isAdmin, 'path=', location.pathname);

  return (
    <>
      {shouldShowNavbar && <Navbar />}
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            isAuthenticated ? <CodeReviewSystem /> : <Navigate to="/login" replace />
          }
        />
        <Route
          path="/admin"
          element={
            isAuthenticated && isAdmin ? (
              <AdminPanel />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route path="*" element={<Navigate to="/login" replace />} />
        <Route path="/dashboard" element={<CodeReviewSystem/>}/>
      </Routes>
    </>
  );
}

export default App;
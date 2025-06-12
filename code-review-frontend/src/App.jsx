import React from 'react';
import { useLocation } from 'react-router'
import { Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from './components/LoginPage';
import CodeReviewSystem from './components/CodeReviewSystem';
import './index.css';
import Navbar from './components/Navbar';

function App() {
  const token = localStorage.getItem('admin_token');
  const isAuthenticated = !!token;
  const location = useLocation();
  const hideNavbarRoutes = ['/login'];
  const shouldShowNavbar = !hideNavbarRoutes.includes(location.pathname);

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
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </>
  );
}

export default App;
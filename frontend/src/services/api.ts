import axios from 'axios';
import { Feature, User, Analysis, AuthResponse } from '../types';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

//add token to requests if it exists
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

//info endpoints
export const getFeatures = async (): Promise<Feature[]> => {
  const response = await api.get('/info/features');
  return response.data.features;
};

export const healthCheck = async () => {
  const response = await api.get('/info/health');
  return response.data;
};

//auth endpoints 
export const register = async (email: string, password: string): Promise<AuthResponse> => {
  const response = await api.post('/auth/register', { email, password });
  return response.data;
};

export const login = async (email: string, password: string): Promise<AuthResponse> => {
  const response = await api.post('/auth/login', { email, password });
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('user');
};

export default api;
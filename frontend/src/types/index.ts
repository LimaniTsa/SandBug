export interface Feature {
  id: number;
  title: string;
  description: string;
  icon: string;
}

export interface User {
  id: number;
  email: string;
  created_at: string;
  last_login?: string;
}

export interface Analysis {
  id: number;
  filename: string;
  file_hash: string;
  file_size: number;
  file_type?: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  risk_level?: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  submitted_at: string;
  completed_at?: string;
  ai_summary?: string;
}

export interface AuthResponse {
  access_token: string;
  user: User;
}
import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders the peer chat header', () => {
  render(<App />);
  const headingElement = screen.getByText(/peerjs direct chat/i);
  expect(headingElement).toBeInTheDocument();
});

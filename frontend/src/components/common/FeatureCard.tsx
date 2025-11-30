import React from 'react';
import { LucideIcon } from 'lucide-react';
import './FeatureCard.css';

interface FeatureCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
}

const FeatureCard: React.FC<FeatureCardProps> = ({
  icon: Icon,
  title,
  description
}) => {
  const handleMove: React.MouseEventHandler<HTMLDivElement> = (e) => {
    const card = e.currentTarget;
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    card.style.setProperty("--mouse-x", `${x}px`);
    card.style.setProperty("--mouse-y", `${y}px`);
  };

  return (
    <div
      className="feature-card chroma-card"
      onMouseMove={handleMove}
    >
      <div className="feature-icon">
        <Icon size={32} />
      </div>

      <h3 className="feature-title">{title}</h3>
      <p className="feature-description">{description}</p>
    </div>
  );
};

export default FeatureCard;

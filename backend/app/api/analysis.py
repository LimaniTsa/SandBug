from flask import request, jsonify, current_app
from app.api import analysis_bp
from app.models import db, Analysis
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.utils import secure_filename
import os
import hashlib
import magic
from datetime import datetime

def allowed_file(filename):
    #Check if file extension is allowed
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def get_file_hash(file_path):
    #Calculate SHA256 hash of file
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_type(file_path):
    #Detect actual file type using python-magic
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except:
        return "unknown"

@analysis_bp.route('/upload', methods=['POST'])
def upload_file():
 
    #upload file for analysis for both authenticated users and guests
    try:
        #check if user is authenticated
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
        except:
            pass #guest user
        
        #check if file is in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        #check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        #validate file extension
        if not allowed_file(file.filename):
            return jsonify({
                'error': f'File type not allowed. Allowed types: {", ".join(current_app.config["ALLOWED_EXTENSIONS"])}'
            }), 400
        
        #secure the filename
        original_filename = secure_filename(file.filename)
        
        #create unique filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{original_filename}"
        
        #save file temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        
        #get file information
        file_size = os.path.getsize(file_path)
        file_hash = get_file_hash(file_path)
        file_type = get_file_type(file_path)
        
        #check for duplicate analysis (authenticated users)
        if user_id:
            existing_analysis = Analysis.query.filter_by(
                user_id=user_id,
                file_hash=file_hash
            ).first()
            
            if existing_analysis:
                #remove duplicate file
                os.remove(file_path)
                return jsonify({
                    'message': 'File already analysed',
                    'duplicate': True,
                    'analysis_id': existing_analysis.id,
                    'analysis': existing_analysis.to_dict()
                }), 200
        
        #create analysis record
        new_analysis = Analysis(
            user_id=user_id,
            filename=original_filename,
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type,
            status='pending'
        )
        
        db.session.add(new_analysis)
        db.session.commit()
        
        # note: need to add queue analysis task (sprint 8)
        
        return jsonify({
            'message': 'File uploaded successfully',
            'analysis': new_analysis.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@analysis_bp.route('/<int:analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    #get analysis by ID
    try:
        #check if user is authenticated
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
        except:
            pass
        
        analysis = Analysis.query.get(analysis_id)
        
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        
        #check if user has access to analysis
        if analysis.user_id and analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        return jsonify({'analysis': analysis.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get analysis: {str(e)}'}), 500

@analysis_bp.route('/history', methods=['GET'])
@jwt_required()
def get_user_analyses():
    #get all analyses for authenticated user
    try:
        user_id = get_jwt_identity()
        
        #get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        #get filter parameters
        status = request.args.get('status')
        risk_level = request.args.get('risk_level')
        
        #build query
        query = Analysis.query.filter_by(user_id=user_id)
        
        if status:
            query = query.filter_by(status=status)
        if risk_level:
            query = query.filter_by(risk_level=risk_level)
        
        #order by most recent first
        query = query.order_by(Analysis.submitted_at.desc())
        
        #paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'analyses': [analysis.to_dict() for analysis in pagination.items],
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get analyses: {str(e)}'}), 500

@analysis_bp.route('/<int:analysis_id>', methods=['DELETE'])
@jwt_required()
def delete_analysis(analysis_id):
    #delete analysis (for authenticated users)
    try:
        user_id = get_jwt_identity()
        
        analysis = Analysis.query.get(analysis_id)
        
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        
        #check if user owns this analysis
        if analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        #delete file if it exists
        upload_folder = current_app.config['UPLOAD_FOLDER']
        file_path = os.path.join(upload_folder, f"*_{analysis.filename}")
       
        #note: need to implement file deletion logic
        
        #delete from database
        db.session.delete(analysis)
        db.session.commit()
        
        return jsonify({'message': 'Analysis deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete analysis: {str(e)}'}), 500
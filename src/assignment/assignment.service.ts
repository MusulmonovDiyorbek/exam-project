import { Injectable } from '@nestjs/common';
import { CreateAssignmentDto } from './dto/create-assignment.dto';
import { UpdateAssignmentDto } from './dto/update-assignment.dto';
import { Repository } from 'typeorm';
import { Assignment } from './entities/assignment.entity';
import { ModelService } from 'src/model/model.service';
import { EnrollmentService } from 'src/enrollment/enrollment.service';
import { User } from 'src/users/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class AssignmentService {
  constructor(
    @InjectRepository(Assignment)
    private readonly assigmentRepo: Repository<Assignment>,
    private readonly modelService: ModelService,
    private readonly enrollmentService: EnrollmentService,
  ) { }

  async create(student: User, dto: CreateAssignmentDto) {
    const model = await this.modelService.findOne(dto.modelId);
    const courseId = model.course.id;
    const enrolled = await this.enrollmentService.isEnrolled(student.id, courseId);
    if (!enrolled) {
      throw new Error('Siz bu kursga yozilmagansiz');
    }
    const assignment = this.assigmentRepo.create({
      content: dto.content,
      model,
      student,
    });
    return this.assigmentRepo.save(assignment)
  } 

  async findByModel(modelId: number) {
    return this.assigmentRepo.find({ where: { model: { id: modelId } }, relations: ['student'] })
  }

  async findOneById(id: number) {
    const assignment = await this.assigmentRepo.findOne({ where: { id } });
    if(!assignment){
      throw new Error ('assignment topilmadi')
    }
    return assignment
  }
 
  async update(id:number,dto:UpdateAssignmentDto){
    const assignment = await this.findOneById(id)
    if(!assignment){
      throw new Error ('bunday assignment mavjud emas')
    }
    Object.assign(assignment,dto)
    return this.assigmentRepo.save(assignment)
  }

  async remove(id:number){
    const assignment = await this.findOneById(id)
    if(!assignment){
      throw new Error ('bunday assignment mavjud emas')
    }
    return this.assigmentRepo.remove(assignment)
  }

}

